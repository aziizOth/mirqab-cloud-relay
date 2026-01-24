#!/bin/bash
set -e

# Deploy Mirqab Cloud Relay to GCP
# Prerequisites: gcloud CLI, terraform, kubectl, helm

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Configuration
GCP_PROJECT="${GCP_PROJECT:-}"
GCP_REGION="${GCP_REGION:-me-central2}"
DEPLOYMENT_TYPE="${DEPLOYMENT_TYPE:-gke}"  # gke, cloudrun, or vm
CLUSTER_NAME="${CLUSTER_NAME:-mirqab-cloud-relay}"

echo "============================================"
echo "  Mirqab Cloud Relay - GCP Deployment"
echo "============================================"
echo "Project: $GCP_PROJECT"
echo "Region: $GCP_REGION"
echo "Type: $DEPLOYMENT_TYPE"
echo ""

# Validate prerequisites
check_prerequisites() {
    echo "[0/6] Checking prerequisites..."

    if ! command -v gcloud &> /dev/null; then
        echo "ERROR: gcloud CLI not found. Install from: https://cloud.google.com/sdk/docs/install"
        exit 1
    fi

    if ! command -v terraform &> /dev/null; then
        echo "ERROR: terraform not found. Install from: https://terraform.io/downloads"
        exit 1
    fi

    if [ -z "$GCP_PROJECT" ]; then
        echo "ERROR: GCP_PROJECT environment variable not set"
        echo "Usage: GCP_PROJECT=your-project-id ./deploy-to-gcp.sh"
        exit 1
    fi

    # Verify gcloud authentication
    if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" | grep -q .; then
        echo "ERROR: Not authenticated with gcloud. Run: gcloud auth login"
        exit 1
    fi

    echo "Prerequisites OK"
}

# Enable required GCP APIs
enable_apis() {
    echo "[1/6] Enabling GCP APIs..."
    gcloud services enable \
        container.googleapis.com \
        run.googleapis.com \
        compute.googleapis.com \
        cloudbuild.googleapis.com \
        artifactregistry.googleapis.com \
        secretmanager.googleapis.com \
        sqladmin.googleapis.com \
        redis.googleapis.com \
        dns.googleapis.com \
        --project=$GCP_PROJECT
}

# Deploy infrastructure with Terraform
deploy_terraform() {
    echo "[2/6] Deploying infrastructure with Terraform..."
    cd "$PROJECT_DIR/terraform/gcp"

    # Initialize Terraform
    terraform init

    # Create terraform.tfvars if not exists
    if [ ! -f terraform.tfvars ]; then
        cat > terraform.tfvars << EOF
project_id = "$GCP_PROJECT"
region = "$GCP_REGION"
environment = "prod"
budget_monthly_amount = 500
enable_cloud_armor = true
EOF
    fi

    # Plan and apply
    terraform plan -out=tfplan
    terraform apply tfplan

    cd "$SCRIPT_DIR"
}

# Build and push container images
build_images() {
    echo "[3/6] Building and pushing container images..."

    # Create Artifact Registry repository if not exists
    gcloud artifacts repositories create mirqab-cloud-relay \
        --repository-format=docker \
        --location=$GCP_REGION \
        --project=$GCP_PROJECT \
        2>/dev/null || true

    # Configure Docker for GCP
    gcloud auth configure-docker ${GCP_REGION}-docker.pkg.dev --quiet

    REGISTRY="${GCP_REGION}-docker.pkg.dev/${GCP_PROJECT}/mirqab-cloud-relay"

    # Build each service
    for service in api-gateway http-c2 c2-dns exfil-server payload-server orchestrator; do
        echo "Building $service..."
        SERVICE_DIR="$PROJECT_DIR/services/$service"
        if [ -d "$SERVICE_DIR" ] && [ -f "$SERVICE_DIR/Dockerfile" ]; then
            docker build -t "$REGISTRY/$service:latest" "$SERVICE_DIR"
            docker push "$REGISTRY/$service:latest"
        fi
    done
}

# Deploy to GKE
deploy_gke() {
    echo "[4/6] Deploying to GKE..."

    # Get cluster credentials
    gcloud container clusters get-credentials $CLUSTER_NAME \
        --region $GCP_REGION \
        --project $GCP_PROJECT

    # Create namespace
    kubectl create namespace mirqab 2>/dev/null || true

    # Apply Kubernetes manifests
    kubectl apply -k "$PROJECT_DIR/kubernetes/overlays/gcp" -n mirqab

    # Wait for deployments
    kubectl rollout status deployment/api-gateway -n mirqab --timeout=300s
    kubectl rollout status deployment/http-c2 -n mirqab --timeout=300s
}

# Deploy to Cloud Run
deploy_cloudrun() {
    echo "[4/6] Deploying to Cloud Run..."

    REGISTRY="${GCP_REGION}-docker.pkg.dev/${GCP_PROJECT}/mirqab-cloud-relay"

    for service in api-gateway http-c2 exfil-server payload-server; do
        echo "Deploying $service to Cloud Run..."
        gcloud run deploy "mirqab-$service" \
            --image="$REGISTRY/$service:latest" \
            --region=$GCP_REGION \
            --platform=managed \
            --allow-unauthenticated \
            --memory=512Mi \
            --cpu=1 \
            --min-instances=0 \
            --max-instances=10 \
            --project=$GCP_PROJECT
    done
}

# Deploy to Compute Engine VM
deploy_vm() {
    echo "[4/6] Deploying to Compute Engine VM..."

    VM_NAME="mirqab-cloud-relay"

    # Create VM if not exists
    if ! gcloud compute instances describe $VM_NAME --zone=${GCP_REGION}-a --project=$GCP_PROJECT &>/dev/null; then
        gcloud compute instances create $VM_NAME \
            --machine-type=e2-standard-4 \
            --zone=${GCP_REGION}-a \
            --image-family=ubuntu-2204-lts \
            --image-project=ubuntu-os-cloud \
            --boot-disk-size=100GB \
            --boot-disk-type=pd-ssd \
            --tags=http-server,https-server,mirqab-relay \
            --project=$GCP_PROJECT

        # Wait for VM to be ready
        sleep 60
    fi

    # Get external IP
    EXTERNAL_IP=$(gcloud compute instances describe $VM_NAME \
        --zone=${GCP_REGION}-a \
        --project=$GCP_PROJECT \
        --format='get(networkInterfaces[0].accessConfigs[0].natIP)')

    echo "VM IP: $EXTERNAL_IP"

    # Copy files and install
    gcloud compute scp --recurse \
        "$PROJECT_DIR/services" \
        "$PROJECT_DIR/docker-compose.yml" \
        "$SCRIPT_DIR/install.sh" \
        $VM_NAME:/tmp/ \
        --zone=${GCP_REGION}-a \
        --project=$GCP_PROJECT

    gcloud compute ssh $VM_NAME \
        --zone=${GCP_REGION}-a \
        --project=$GCP_PROJECT \
        --command="sudo bash /tmp/install.sh && sudo cp -r /tmp/services /tmp/docker-compose.yml /opt/mirqab/cloud-relay/ && cd /opt/mirqab/cloud-relay && sudo docker compose up -d"
}

# Configure DNS
configure_dns() {
    echo "[5/6] Configuring DNS..."
    # This would configure Cloud DNS if needed
    echo "DNS configuration skipped (manual setup required)"
}

# Print summary
print_summary() {
    echo ""
    echo "============================================"
    echo "  Deployment Complete!"
    echo "============================================"
    echo ""

    case $DEPLOYMENT_TYPE in
        gke)
            INGRESS_IP=$(kubectl get ingress -n mirqab -o jsonpath='{.items[0].status.loadBalancer.ingress[0].ip}' 2>/dev/null || echo "pending")
            echo "GKE Cluster: $CLUSTER_NAME"
            echo "Ingress IP: $INGRESS_IP"
            echo ""
            echo "Commands:"
            echo "  kubectl get pods -n mirqab"
            echo "  kubectl logs -f deployment/api-gateway -n mirqab"
            ;;
        cloudrun)
            API_URL=$(gcloud run services describe mirqab-api-gateway --region=$GCP_REGION --format='value(status.url)')
            echo "Cloud Run Services deployed"
            echo "API Gateway: $API_URL"
            ;;
        vm)
            echo "VM: $VM_NAME"
            echo "External IP: $EXTERNAL_IP"
            echo ""
            echo "Access:"
            echo "  API Gateway: http://$EXTERNAL_IP:8000"
            echo "  HTTP C2:     http://$EXTERNAL_IP:8080"
            echo "  Grafana:     http://$EXTERNAL_IP:3000"
            ;;
    esac
}

# Main execution
main() {
    check_prerequisites
    enable_apis
    deploy_terraform
    build_images

    case $DEPLOYMENT_TYPE in
        gke)
            deploy_gke
            ;;
        cloudrun)
            deploy_cloudrun
            ;;
        vm)
            deploy_vm
            ;;
        *)
            echo "Unknown deployment type: $DEPLOYMENT_TYPE"
            exit 1
            ;;
    esac

    configure_dns
    print_summary
}

# Run
main "$@"
