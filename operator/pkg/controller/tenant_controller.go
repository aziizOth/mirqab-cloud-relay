// Mirqab Cloud Relay - Tenant Controller
package controller

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	appsv1 "k8s.io/api/apps/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	mirqabv1 "mirqab-cloud-relay/operator/pkg/apis/mirqab/v1"
)

// cert-manager Certificate GVK
var certificateGVK = schema.GroupVersionKind{
	Group:   "cert-manager.io",
	Version: "v1",
	Kind:    "Certificate",
}

const (
	tenantFinalizer   = "mirqab.io/tenant-finalizer"
	baseDomain        = "relay.mirqab.io"
	c2DnsDomain       = "c2.mirqab.io"
	imageTag          = "latest"
	imageRegistry     = "ghcr.io/mirqab/cloud-relay"
	licenseSecretName = "mirqab-license-secret"
)

// TenantReconciler reconciles a Tenant object
type TenantReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=mirqab.io,resources=tenants,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=mirqab.io,resources=tenants/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=mirqab.io,resources=tenants/finalizers,verbs=update
// +kubebuilder:rbac:groups=core,resources=namespaces,verbs=get;list;watch;create;update;delete
// +kubebuilder:rbac:groups=core,resources=secrets;configmaps;services;serviceaccounts,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies;ingresses,verbs=get;list;watch;create;update;patch;delete

// Reconcile handles tenant lifecycle
func (r *TenantReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Fetch the Tenant
	tenant := &mirqabv1.Tenant{}
	if err := r.Get(ctx, req.NamespacedName, tenant); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// Check if being deleted
	if !tenant.ObjectMeta.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, tenant)
	}

	// Add finalizer if not present
	if !controllerutil.ContainsFinalizer(tenant, tenantFinalizer) {
		controllerutil.AddFinalizer(tenant, tenantFinalizer)
		if err := r.Update(ctx, tenant); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	// Main reconciliation logic
	logger.Info("Reconciling tenant", "name", tenant.Name, "tier", tenant.Spec.Tier)

	// Initialize status if needed
	if tenant.Status.Phase == "" {
		tenant.Status.Phase = mirqabv1.PhasePending
		if err := r.Status().Update(ctx, tenant); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	// Validate license
	if err := r.validateLicense(ctx, tenant); err != nil {
		logger.Error(err, "License validation failed")
		tenant.Status.Phase = mirqabv1.PhaseFailed
		r.setCondition(tenant, mirqabv1.ConditionLicenseValid, metav1.ConditionFalse, "ValidationFailed", err.Error())
		r.Status().Update(ctx, tenant)
		return ctrl.Result{RequeueAfter: time.Hour}, nil
	}
	r.setCondition(tenant, mirqabv1.ConditionLicenseValid, metav1.ConditionTrue, "Valid", "License validated successfully")

	// Generate tenant ID if not set
	if tenant.Status.TenantID == "" {
		tenant.Status.TenantID = r.generateTenantID(tenant.Spec.OrganizationName)
		tenant.Status.Namespace = fmt.Sprintf("tenant-%s", tenant.Status.TenantID)
		tenant.Status.Phase = mirqabv1.PhaseProvisioning
		if err := r.Status().Update(ctx, tenant); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	// Provision namespace
	if err := r.reconcileNamespace(ctx, tenant); err != nil {
		logger.Error(err, "Failed to reconcile namespace")
		return ctrl.Result{}, err
	}

	// Provision secrets
	if err := r.reconcileSecrets(ctx, tenant); err != nil {
		logger.Error(err, "Failed to reconcile secrets")
		return ctrl.Result{}, err
	}

	// Provision mTLS client certificate
	if err := r.reconcileMTLSCertificate(ctx, tenant); err != nil {
		logger.Error(err, "Failed to reconcile mTLS certificate")
		return ctrl.Result{}, err
	}

	// Provision network policies
	if err := r.reconcileNetworkPolicies(ctx, tenant); err != nil {
		logger.Error(err, "Failed to reconcile network policies")
		return ctrl.Result{}, err
	}

	// Provision C2 HTTP service
	if tenant.Spec.Features.C2Http || tenant.Spec.Tier != "" {
		if err := r.reconcileC2Http(ctx, tenant); err != nil {
			logger.Error(err, "Failed to reconcile C2 HTTP")
			return ctrl.Result{}, err
		}
	}

	// Provision C2 DNS service (if enabled)
	if tenant.Spec.Features.C2Dns {
		if err := r.reconcileC2Dns(ctx, tenant); err != nil {
			logger.Error(err, "Failed to reconcile C2 DNS")
			return ctrl.Result{}, err
		}
	}

	// Provision Payload server
	if tenant.Spec.Features.PayloadHosting || tenant.Spec.Tier != "" {
		if err := r.reconcilePayloadServer(ctx, tenant); err != nil {
			logger.Error(err, "Failed to reconcile payload server")
			return ctrl.Result{}, err
		}
	}

	// Provision Ingress resources
	if err := r.reconcileIngress(ctx, tenant); err != nil {
		logger.Error(err, "Failed to reconcile ingress")
		return ctrl.Result{}, err
	}

	// Update endpoints
	tenant.Status.Endpoints = mirqabv1.TenantEndpoints{
		C2Http:   fmt.Sprintf("https://c2-http.%s.%s", tenant.Status.TenantID, baseDomain),
		Payloads: fmt.Sprintf("https://payloads.%s.%s", tenant.Status.TenantID, baseDomain),
	}
	if tenant.Spec.Features.C2Dns {
		tenant.Status.Endpoints.C2Dns = fmt.Sprintf("%s.%s", tenant.Status.TenantID, c2DnsDomain)
	}

	// Set expiration
	validityDays := mirqabv1.TierValidityDays(tenant.Spec.Tier)
	expiresAt := metav1.NewTime(time.Now().AddDate(0, 0, validityDays))
	tenant.Status.LicenseExpiresAt = &expiresAt

	// Check all conditions and set Ready
	if r.allConditionsReady(tenant) {
		tenant.Status.Phase = mirqabv1.PhaseActive
		r.setCondition(tenant, mirqabv1.ConditionReady, metav1.ConditionTrue, "AllResourcesReady", "Tenant is fully provisioned")
	}

	tenant.Status.ObservedGeneration = tenant.Generation
	tenant.Status.LastHealthCheck = &metav1.Time{Time: time.Now()}

	if err := r.Status().Update(ctx, tenant); err != nil {
		return ctrl.Result{}, err
	}

	logger.Info("Tenant reconciled successfully", "name", tenant.Name, "phase", tenant.Status.Phase)
	return ctrl.Result{RequeueAfter: 5 * time.Minute}, nil
}

// reconcileDelete handles tenant deletion
func (r *TenantReconciler) reconcileDelete(ctx context.Context, tenant *mirqabv1.Tenant) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("Deleting tenant", "name", tenant.Name)

	tenant.Status.Phase = mirqabv1.PhaseTerminating
	r.Status().Update(ctx, tenant)

	// Delete namespace (cascades to all resources)
	ns := &corev1.Namespace{}
	if err := r.Get(ctx, types.NamespacedName{Name: tenant.Status.Namespace}, ns); err == nil {
		if err := r.Delete(ctx, ns); err != nil && !errors.IsNotFound(err) {
			return ctrl.Result{}, err
		}
		// Wait for namespace deletion
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}

	// Remove finalizer
	controllerutil.RemoveFinalizer(tenant, tenantFinalizer)
	if err := r.Update(ctx, tenant); err != nil {
		return ctrl.Result{}, err
	}

	logger.Info("Tenant deleted", "name", tenant.Name)
	return ctrl.Result{}, nil
}

// validateLicense validates the tenant's license key
func (r *TenantReconciler) validateLicense(ctx context.Context, tenant *mirqabv1.Tenant) error {
	// Parse license key format: MIRQAB-{TIER}-{CHECKSUM}-{RANDOM}
	parts := strings.Split(strings.ToUpper(tenant.Spec.LicenseKey), "-")
	if len(parts) != 4 {
		return fmt.Errorf("invalid license key format")
	}

	if parts[0] != "MIRQAB" {
		return fmt.Errorf("invalid license key prefix")
	}

	// Verify tier matches
	tierMap := map[string]mirqabv1.TenantTier{
		"TRL": mirqabv1.TierTrial,
		"POC": mirqabv1.TierPOC,
		"STR": mirqabv1.TierStarter,
		"PRO": mirqabv1.TierProfessional,
		"ENT": mirqabv1.TierEnterprise,
	}

	licenseTier, ok := tierMap[parts[1]]
	if !ok {
		return fmt.Errorf("unknown tier code: %s", parts[1])
	}

	if licenseTier != tenant.Spec.Tier {
		return fmt.Errorf("license tier mismatch: license=%s, spec=%s", licenseTier, tenant.Spec.Tier)
	}

	// In production, verify checksum against license server
	// For now, just verify format
	if len(parts[2]) != 8 || len(parts[3]) < 8 {
		return fmt.Errorf("invalid license key structure")
	}

	return nil
}

// generateTenantID creates a unique tenant identifier
func (r *TenantReconciler) generateTenantID(orgName string) string {
	slug := strings.ToLower(orgName)
	slug = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			return r
		}
		return '-'
	}, slug)
	if len(slug) > 20 {
		slug = slug[:20]
	}
	slug = strings.Trim(slug, "-")

	suffix := make([]byte, 4)
	rand.Read(suffix)
	return fmt.Sprintf("%s-%s", slug, hex.EncodeToString(suffix))
}

// generateAPIKey creates a secure API key
func (r *TenantReconciler) generateAPIKey() string {
	key := make([]byte, 24)
	rand.Read(key)
	return fmt.Sprintf("cr_live_%s", hex.EncodeToString(key))
}

// setCondition updates a condition on the tenant
func (r *TenantReconciler) setCondition(tenant *mirqabv1.Tenant, condType mirqabv1.ConditionType, status metav1.ConditionStatus, reason, message string) {
	tenant.SetCondition(mirqabv1.TenantCondition{
		Type:               condType,
		Status:             status,
		LastTransitionTime: metav1.Now(),
		Reason:             reason,
		Message:            message,
	})
}

// allConditionsReady checks if all required conditions are ready
func (r *TenantReconciler) allConditionsReady(tenant *mirqabv1.Tenant) bool {
	required := []mirqabv1.ConditionType{
		mirqabv1.ConditionLicenseValid,
		mirqabv1.ConditionNamespaceReady,
		mirqabv1.ConditionC2HttpReady,
		mirqabv1.ConditionCertificatesReady,
	}

	for _, ct := range required {
		cond := tenant.GetCondition(ct)
		if cond == nil || cond.Status != metav1.ConditionTrue {
			return false
		}
	}
	return true
}

// reconcileNamespace ensures the tenant namespace exists
func (r *TenantReconciler) reconcileNamespace(ctx context.Context, tenant *mirqabv1.Tenant) error {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: tenant.Status.Namespace,
			Labels: map[string]string{
				"mirqab.io/tenant-id":                  tenant.Status.TenantID,
				"mirqab.io/tier":                       string(tenant.Spec.Tier),
				"pod-security.kubernetes.io/enforce":  "restricted",
				"pod-security.kubernetes.io/audit":    "restricted",
				"pod-security.kubernetes.io/warn":     "restricted",
			},
			Annotations: map[string]string{
				"mirqab.io/organization": tenant.Spec.OrganizationName,
				"mirqab.io/admin-email":  tenant.Spec.AdminEmail,
			},
		},
	}

	if err := r.Create(ctx, ns); err != nil {
		if !errors.IsAlreadyExists(err) {
			return err
		}
	}

	// Create ResourceQuota
	cpuLimit, memLimit, maxPods := mirqabv1.TierQuotas(tenant.Spec.Tier)
	quota := &corev1.ResourceQuota{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tenant-quota",
			Namespace: tenant.Status.Namespace,
		},
		Spec: corev1.ResourceQuotaSpec{
			Hard: corev1.ResourceList{
				corev1.ResourcePods:           resource.MustParse(fmt.Sprintf("%d", maxPods)),
				corev1.ResourceLimitsCPU:      resource.MustParse(cpuLimit),
				corev1.ResourceLimitsMemory:   resource.MustParse(memLimit),
				corev1.ResourceRequestsCPU:    resource.MustParse(cpuLimit),
				corev1.ResourceRequestsMemory: resource.MustParse(memLimit),
			},
		},
	}

	if err := r.Create(ctx, quota); err != nil {
		if !errors.IsAlreadyExists(err) {
			return err
		}
	}

	r.setCondition(tenant, mirqabv1.ConditionNamespaceReady, metav1.ConditionTrue, "Created", "Namespace created successfully")
	return nil
}

// reconcileSecrets creates tenant secrets
func (r *TenantReconciler) reconcileSecrets(ctx context.Context, tenant *mirqabv1.Tenant) error {
	// Generate API key if not set
	if tenant.Status.APIKey == "" {
		tenant.Status.APIKey = r.generateAPIKey()
	}

	// Create credentials secret
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tenant-credentials",
			Namespace: tenant.Status.Namespace,
			Labels: map[string]string{
				"mirqab.io/tenant-id": tenant.Status.TenantID,
			},
		},
		Type: corev1.SecretTypeOpaque,
		StringData: map[string]string{
			"api-key":      tenant.Status.APIKey,
			"tenant-id":    tenant.Status.TenantID,
			"license-key":  tenant.Spec.LicenseKey,
			"admin-email":  tenant.Spec.AdminEmail,
		},
	}

	if err := r.Create(ctx, secret); err != nil {
		if !errors.IsAlreadyExists(err) {
			return err
		}
	}

	tenant.Status.CertificateSecretRef = "tenant-credentials"
	return nil
}

// reconcileMTLSCertificate creates mTLS client certificate for tenant
func (r *TenantReconciler) reconcileMTLSCertificate(ctx context.Context, tenant *mirqabv1.Tenant) error {
	// Create cert-manager Certificate using unstructured to avoid importing cert-manager types
	cert := &unstructured.Unstructured{}
	cert.SetGroupVersionKind(certificateGVK)
	cert.SetName("tenant-mtls-cert")
	cert.SetNamespace(tenant.Status.Namespace)
	cert.SetLabels(map[string]string{
		"mirqab.io/tenant-id": tenant.Status.TenantID,
		"mirqab.io/component": "mtls",
	})

	// Calculate certificate duration based on tier
	duration := "2160h" // 90 days default
	renewBefore := "360h" // 15 days
	if tenant.Spec.Tier == mirqabv1.TierEnterprise {
		duration = "8760h" // 1 year for enterprise
		renewBefore = "720h" // 30 days
	}

	// Set the spec
	cert.Object["spec"] = map[string]interface{}{
		"secretName":  "tenant-mtls-secret",
		"duration":    duration,
		"renewBefore": renewBefore,
		"subject": map[string]interface{}{
			"organizations":       []string{tenant.Spec.OrganizationName},
			"organizationalUnits": []string{"Cloud Relay Client"},
		},
		"commonName": fmt.Sprintf("%s.tenant.mirqab.io", tenant.Status.TenantID),
		"usages": []string{
			"client auth",
			"key encipherment",
			"digital signature",
		},
		"privateKey": map[string]interface{}{
			"algorithm": "ECDSA",
			"size":      256,
		},
		"issuerRef": map[string]interface{}{
			"name":  "mirqab-mtls-issuer",
			"kind":  "Issuer",
			"group": "cert-manager.io",
		},
	}

	// Create the certificate
	if err := r.Create(ctx, cert); err != nil {
		if !errors.IsAlreadyExists(err) {
			return err
		}
	}

	// Create ConfigMap with CA bundle for tenant to verify Master
	caBundle := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "mirqab-ca-bundle",
			Namespace: tenant.Status.Namespace,
			Labels: map[string]string{
				"mirqab.io/tenant-id": tenant.Status.TenantID,
			},
		},
		Data: map[string]string{
			"master-url": fmt.Sprintf("https://api.%s", baseDomain),
			"ca-issuer":  "mirqab-mtls-issuer",
		},
	}

	if err := r.Create(ctx, caBundle); err != nil {
		if !errors.IsAlreadyExists(err) {
			return err
		}
	}

	// Update status with certificate reference
	tenant.Status.CertificateSecretRef = "tenant-mtls-secret"
	return nil
}

// reconcileNetworkPolicies creates network policies for tenant isolation
func (r *TenantReconciler) reconcileNetworkPolicies(ctx context.Context, tenant *mirqabv1.Tenant) error {
	// Default deny all ingress
	denyAll := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "default-deny-all",
			Namespace: tenant.Status.Namespace,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
				networkingv1.PolicyTypeEgress,
			},
		},
	}

	if err := r.Create(ctx, denyAll); err != nil && !errors.IsAlreadyExists(err) {
		return err
	}

	// Allow ingress from ingress controller
	allowIngress := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "allow-ingress",
			Namespace: tenant.Status.Namespace,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From: []networkingv1.NetworkPolicyPeer{{
					NamespaceSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"app.kubernetes.io/name": "ingress-nginx",
						},
					},
				}},
			}},
		},
	}

	if err := r.Create(ctx, allowIngress); err != nil && !errors.IsAlreadyExists(err) {
		return err
	}

	// Allow DNS egress
	allowDNS := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "allow-dns",
			Namespace: tenant.Status.Namespace,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			Egress: []networkingv1.NetworkPolicyEgressRule{{
				To: []networkingv1.NetworkPolicyPeer{{
					NamespaceSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"kubernetes.io/metadata.name": "kube-system",
						},
					},
				}},
				Ports: []networkingv1.NetworkPolicyPort{{
					Protocol: func() *corev1.Protocol { p := corev1.ProtocolUDP; return &p }(),
					Port:     &intstr.IntOrString{IntVal: 53},
				}},
			}},
		},
	}

	if err := r.Create(ctx, allowDNS); err != nil && !errors.IsAlreadyExists(err) {
		return err
	}

	return nil
}

// reconcileC2Http creates C2 HTTP deployment
func (r *TenantReconciler) reconcileC2Http(ctx context.Context, tenant *mirqabv1.Tenant) error {
	labels := map[string]string{
		"app":                 "c2-http",
		"mirqab.io/tenant-id": tenant.Status.TenantID,
		"mirqab.io/component": "c2-service",
	}

	replicas := int32(2)

	deploy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "c2-http",
			Namespace: tenant.Status.Namespace,
			Labels:    labels,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: labels,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels,
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: "default",
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot: func() *bool { b := true; return &b }(),
						RunAsUser:    func() *int64 { i := int64(65534); return &i }(),
						FSGroup:      func() *int64 { i := int64(65534); return &i }(),
						SeccompProfile: &corev1.SeccompProfile{
							Type: corev1.SeccompProfileTypeRuntimeDefault,
						},
					},
					Containers: []corev1.Container{{
						Name:  "c2-http",
						Image: fmt.Sprintf("%s/c2-http:%s", imageRegistry, imageTag),
						Ports: []corev1.ContainerPort{
							{Name: "http", ContainerPort: 8080},
							{Name: "metrics", ContainerPort: 9090},
						},
						Env: []corev1.EnvVar{
							{Name: "TENANT_ID", Value: tenant.Status.TenantID},
							{Name: "HTTP_PORT", Value: "8080"},
							{Name: "METRICS_PORT", Value: "9090"},
						},
						EnvFrom: []corev1.EnvFromSource{{
							SecretRef: &corev1.SecretEnvSource{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: "tenant-credentials",
								},
							},
						}},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("50m"),
								corev1.ResourceMemory: resource.MustParse("64Mi"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("200m"),
								corev1.ResourceMemory: resource.MustParse("256Mi"),
							},
						},
						SecurityContext: &corev1.SecurityContext{
							AllowPrivilegeEscalation: func() *bool { b := false; return &b }(),
							ReadOnlyRootFilesystem:   func() *bool { b := true; return &b }(),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"ALL"},
							},
						},
						LivenessProbe: &corev1.Probe{
							ProbeHandler: corev1.ProbeHandler{
								HTTPGet: &corev1.HTTPGetAction{
									Path: "/health",
									Port: intstr.FromInt(8080),
								},
							},
							InitialDelaySeconds: 10,
							PeriodSeconds:       10,
						},
						ReadinessProbe: &corev1.Probe{
							ProbeHandler: corev1.ProbeHandler{
								HTTPGet: &corev1.HTTPGetAction{
									Path: "/ready",
									Port: intstr.FromInt(8080),
								},
							},
							InitialDelaySeconds: 5,
							PeriodSeconds:       5,
						},
					}},
				},
			},
		},
	}

	if err := r.Create(ctx, deploy); err != nil && !errors.IsAlreadyExists(err) {
		return err
	}

	// Create service
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "c2-http",
			Namespace: tenant.Status.Namespace,
			Labels:    labels,
		},
		Spec: corev1.ServiceSpec{
			Selector: labels,
			Ports: []corev1.ServicePort{
				{Name: "http", Port: 80, TargetPort: intstr.FromInt(8080)},
				{Name: "metrics", Port: 9090, TargetPort: intstr.FromInt(9090)},
			},
		},
	}

	if err := r.Create(ctx, svc); err != nil && !errors.IsAlreadyExists(err) {
		return err
	}

	r.setCondition(tenant, mirqabv1.ConditionC2HttpReady, metav1.ConditionTrue, "Deployed", "C2 HTTP service deployed")
	return nil
}

// reconcileC2Dns creates C2 DNS deployment
func (r *TenantReconciler) reconcileC2Dns(ctx context.Context, tenant *mirqabv1.Tenant) error {
	labels := map[string]string{
		"app":                 "c2-dns",
		"mirqab.io/tenant-id": tenant.Status.TenantID,
		"mirqab.io/component": "c2-service",
	}

	replicas := int32(2)
	dnsSubdomain := fmt.Sprintf("%s.%s", tenant.Status.TenantID, c2DnsDomain)

	deploy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "c2-dns",
			Namespace: tenant.Status.Namespace,
			Labels:    labels,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: labels,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels,
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: "default",
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot: func() *bool { b := true; return &b }(),
						RunAsUser:    func() *int64 { i := int64(65534); return &i }(),
						FSGroup:      func() *int64 { i := int64(65534); return &i }(),
					},
					Containers: []corev1.Container{{
						Name:  "c2-dns",
						Image: fmt.Sprintf("%s/c2-dns:%s", imageRegistry, imageTag),
						Ports: []corev1.ContainerPort{
							{Name: "dns-udp", ContainerPort: 5353, Protocol: corev1.ProtocolUDP},
							{Name: "dns-tcp", ContainerPort: 5353, Protocol: corev1.ProtocolTCP},
							{Name: "metrics", ContainerPort: 9091},
						},
						Env: []corev1.EnvVar{
							{Name: "TENANT_ID", Value: tenant.Status.TenantID},
							{Name: "BASE_DOMAIN", Value: dnsSubdomain},
							{Name: "DNS_PORT", Value: "5353"},
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("50m"),
								corev1.ResourceMemory: resource.MustParse("64Mi"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("200m"),
								corev1.ResourceMemory: resource.MustParse("256Mi"),
							},
						},
						SecurityContext: &corev1.SecurityContext{
							AllowPrivilegeEscalation: func() *bool { b := false; return &b }(),
							ReadOnlyRootFilesystem:   func() *bool { b := true; return &b }(),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"ALL"},
							},
						},
					}},
				},
			},
		},
	}

	if err := r.Create(ctx, deploy); err != nil && !errors.IsAlreadyExists(err) {
		return err
	}

	// Create LoadBalancer service for DNS
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "c2-dns",
			Namespace: tenant.Status.Namespace,
			Labels:    labels,
			Annotations: map[string]string{
				"external-dns.alpha.kubernetes.io/hostname":        dnsSubdomain,
				"service.beta.kubernetes.io/aws-load-balancer-type": "nlb",
			},
		},
		Spec: corev1.ServiceSpec{
			Type:                  corev1.ServiceTypeLoadBalancer,
			ExternalTrafficPolicy: corev1.ServiceExternalTrafficPolicyTypeLocal,
			Selector:              labels,
			Ports: []corev1.ServicePort{
				{Name: "dns-udp", Port: 53, TargetPort: intstr.FromInt(5353), Protocol: corev1.ProtocolUDP},
				{Name: "dns-tcp", Port: 53, TargetPort: intstr.FromInt(5353), Protocol: corev1.ProtocolTCP},
			},
		},
	}

	if err := r.Create(ctx, svc); err != nil && !errors.IsAlreadyExists(err) {
		return err
	}

	r.setCondition(tenant, mirqabv1.ConditionC2DnsReady, metav1.ConditionTrue, "Deployed", "C2 DNS service deployed")
	return nil
}

// reconcilePayloadServer creates payload server deployment
func (r *TenantReconciler) reconcilePayloadServer(ctx context.Context, tenant *mirqabv1.Tenant) error {
	labels := map[string]string{
		"app":                 "payload-server",
		"mirqab.io/tenant-id": tenant.Status.TenantID,
		"mirqab.io/component": "payload-service",
	}

	replicas := int32(2)
	storageLimit := mirqabv1.TierStorageLimit(tenant.Spec.Tier)

	deploy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "payload-server",
			Namespace: tenant.Status.Namespace,
			Labels:    labels,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: labels,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels,
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: "default",
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot: func() *bool { b := true; return &b }(),
						RunAsUser:    func() *int64 { i := int64(65534); return &i }(),
						FSGroup:      func() *int64 { i := int64(65534); return &i }(),
					},
					Containers: []corev1.Container{{
						Name:  "payload-server",
						Image: fmt.Sprintf("%s/payload-server:%s", imageRegistry, imageTag),
						Ports: []corev1.ContainerPort{
							{Name: "http", ContainerPort: 8080},
							{Name: "metrics", ContainerPort: 9090},
						},
						Env: []corev1.EnvVar{
							{Name: "TENANT_ID", Value: tenant.Status.TenantID},
							{Name: "LISTEN_ADDR", Value: ":8080"},
							{Name: "METRICS_PORT", Value: "9090"},
							{Name: "MAX_PAYLOAD_SIZE", Value: fmt.Sprintf("%d", storageLimit)},
							{Name: "MINIO_ENDPOINT", Value: "minio.mirqab-system.svc:9000"},
							{Name: "MINIO_BUCKET", Value: fmt.Sprintf("tenant-%s", tenant.Status.TenantID)},
						},
						EnvFrom: []corev1.EnvFromSource{{
							SecretRef: &corev1.SecretEnvSource{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: "tenant-credentials",
								},
							},
						}},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("128Mi"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("512Mi"),
							},
						},
						SecurityContext: &corev1.SecurityContext{
							AllowPrivilegeEscalation: func() *bool { b := false; return &b }(),
							ReadOnlyRootFilesystem:   func() *bool { b := true; return &b }(),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"ALL"},
							},
						},
						LivenessProbe: &corev1.Probe{
							ProbeHandler: corev1.ProbeHandler{
								HTTPGet: &corev1.HTTPGetAction{
									Path: "/health",
									Port: intstr.FromInt(8080),
								},
							},
							InitialDelaySeconds: 10,
							PeriodSeconds:       10,
						},
						ReadinessProbe: &corev1.Probe{
							ProbeHandler: corev1.ProbeHandler{
								HTTPGet: &corev1.HTTPGetAction{
									Path: "/ready",
									Port: intstr.FromInt(8080),
								},
							},
							InitialDelaySeconds: 5,
							PeriodSeconds:       5,
						},
					}},
				},
			},
		},
	}

	if err := r.Create(ctx, deploy); err != nil && !errors.IsAlreadyExists(err) {
		return err
	}

	// Create service
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "payload-server",
			Namespace: tenant.Status.Namespace,
			Labels:    labels,
		},
		Spec: corev1.ServiceSpec{
			Selector: labels,
			Ports: []corev1.ServicePort{
				{Name: "http", Port: 80, TargetPort: intstr.FromInt(8080)},
				{Name: "metrics", Port: 9090, TargetPort: intstr.FromInt(9090)},
			},
		},
	}

	if err := r.Create(ctx, svc); err != nil && !errors.IsAlreadyExists(err) {
		return err
	}

	r.setCondition(tenant, mirqabv1.ConditionPayloadReady, metav1.ConditionTrue, "Deployed", "Payload server deployed")
	return nil
}

// reconcileIngress creates Ingress resources for tenant services
func (r *TenantReconciler) reconcileIngress(ctx context.Context, tenant *mirqabv1.Tenant) error {
	labels := map[string]string{
		"mirqab.io/tenant-id": tenant.Status.TenantID,
		"mirqab.io/component": "ingress",
	}

	// C2 HTTP Ingress
	c2HttpHost := fmt.Sprintf("c2-http.%s.%s", tenant.Status.TenantID, baseDomain)
	pathType := networkingv1.PathTypePrefix

	c2HttpIngress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "c2-http-ingress",
			Namespace: tenant.Status.Namespace,
			Labels:    labels,
			Annotations: map[string]string{
				"kubernetes.io/ingress.class":                  "nginx",
				"nginx.ingress.kubernetes.io/ssl-redirect":     "true",
				"nginx.ingress.kubernetes.io/backend-protocol": "HTTP",
				"nginx.ingress.kubernetes.io/proxy-body-size":  "50m",
				"cert-manager.io/cluster-issuer":               "letsencrypt-prod",
			},
		},
		Spec: networkingv1.IngressSpec{
			TLS: []networkingv1.IngressTLS{{
				Hosts:      []string{c2HttpHost},
				SecretName: fmt.Sprintf("c2-http-tls-%s", tenant.Status.TenantID),
			}},
			Rules: []networkingv1.IngressRule{{
				Host: c2HttpHost,
				IngressRuleValue: networkingv1.IngressRuleValue{
					HTTP: &networkingv1.HTTPIngressRuleValue{
						Paths: []networkingv1.HTTPIngressPath{{
							Path:     "/",
							PathType: &pathType,
							Backend: networkingv1.IngressBackend{
								Service: &networkingv1.IngressServiceBackend{
									Name: "c2-http",
									Port: networkingv1.ServiceBackendPort{
										Number: 80,
									},
								},
							},
						}},
					},
				},
			}},
		},
	}

	if err := r.Create(ctx, c2HttpIngress); err != nil && !errors.IsAlreadyExists(err) {
		return err
	}

	// Payload Server Ingress
	payloadHost := fmt.Sprintf("payloads.%s.%s", tenant.Status.TenantID, baseDomain)

	payloadIngress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "payload-server-ingress",
			Namespace: tenant.Status.Namespace,
			Labels:    labels,
			Annotations: map[string]string{
				"kubernetes.io/ingress.class":                  "nginx",
				"nginx.ingress.kubernetes.io/ssl-redirect":     "true",
				"nginx.ingress.kubernetes.io/backend-protocol": "HTTP",
				"nginx.ingress.kubernetes.io/proxy-body-size":  "100m",
				"cert-manager.io/cluster-issuer":               "letsencrypt-prod",
			},
		},
		Spec: networkingv1.IngressSpec{
			TLS: []networkingv1.IngressTLS{{
				Hosts:      []string{payloadHost},
				SecretName: fmt.Sprintf("payload-tls-%s", tenant.Status.TenantID),
			}},
			Rules: []networkingv1.IngressRule{{
				Host: payloadHost,
				IngressRuleValue: networkingv1.IngressRuleValue{
					HTTP: &networkingv1.HTTPIngressRuleValue{
						Paths: []networkingv1.HTTPIngressPath{{
							Path:     "/",
							PathType: &pathType,
							Backend: networkingv1.IngressBackend{
								Service: &networkingv1.IngressServiceBackend{
									Name: "payload-server",
									Port: networkingv1.ServiceBackendPort{
										Number: 80,
									},
								},
							},
						}},
					},
				},
			}},
		},
	}

	if err := r.Create(ctx, payloadIngress); err != nil && !errors.IsAlreadyExists(err) {
		return err
	}

	// Custom domain ingresses (enterprise only)
	if tenant.Spec.Tier == mirqabv1.TierEnterprise && len(tenant.Spec.CustomDomains) > 0 {
		for i, domain := range tenant.Spec.CustomDomains {
			customIngress := &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      fmt.Sprintf("custom-domain-%d", i),
					Namespace: tenant.Status.Namespace,
					Labels:    labels,
					Annotations: map[string]string{
						"kubernetes.io/ingress.class":              "nginx",
						"nginx.ingress.kubernetes.io/ssl-redirect": "true",
						"cert-manager.io/cluster-issuer":           "letsencrypt-prod",
					},
				},
				Spec: networkingv1.IngressSpec{
					TLS: []networkingv1.IngressTLS{{
						Hosts:      []string{domain},
						SecretName: fmt.Sprintf("custom-domain-tls-%d", i),
					}},
					Rules: []networkingv1.IngressRule{{
						Host: domain,
						IngressRuleValue: networkingv1.IngressRuleValue{
							HTTP: &networkingv1.HTTPIngressRuleValue{
								Paths: []networkingv1.HTTPIngressPath{{
									Path:     "/",
									PathType: &pathType,
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "c2-http",
											Port: networkingv1.ServiceBackendPort{
												Number: 80,
											},
										},
									},
								}},
							},
						},
					}},
				},
			}

			if err := r.Create(ctx, customIngress); err != nil && !errors.IsAlreadyExists(err) {
				return err
			}
		}
	}

	r.setCondition(tenant, mirqabv1.ConditionCertificatesReady, metav1.ConditionTrue, "IngressCreated", "Ingress resources created")
	return nil
}

// SetupWithManager sets up the controller with the Manager
func (r *TenantReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&mirqabv1.Tenant{}).
		Owns(&corev1.Namespace{}).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.Service{}).
		Owns(&networkingv1.Ingress{}).
		Complete(r)
}
