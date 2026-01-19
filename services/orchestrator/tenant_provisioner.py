"""
Mirqab Cloud Relay - Tenant Provisioning Service
Handles automatic provisioning of new tenants in Kubernetes
"""

import os
import json
import base64
import hashlib
import secrets
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional, List, Any
from dataclasses import dataclass, asdict
from enum import Enum

import yaml
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("tenant_provisioner")


class TenantTier(Enum):
    TRIAL = "trial"
    STARTER = "starter"
    PROFESSIONAL = "professional"
    ENTERPRISE = "enterprise"


@dataclass
class TenantQuotas:
    """Resource quotas based on tier"""
    cpu_request: str
    cpu_limit: str
    memory_request: str
    memory_limit: str
    max_pods: int
    max_services: int
    max_secrets: int
    max_configmaps: int
    max_pvcs: int
    max_agents: int
    max_concurrent_executions: int


# Tier-based quota configuration
TIER_QUOTAS: Dict[TenantTier, TenantQuotas] = {
    TenantTier.TRIAL: TenantQuotas(
        cpu_request="500m", cpu_limit="1",
        memory_request="512Mi", memory_limit="1Gi",
        max_pods=5, max_services=3, max_secrets=5, max_configmaps=5, max_pvcs=1,
        max_agents=3, max_concurrent_executions=1
    ),
    TenantTier.STARTER: TenantQuotas(
        cpu_request="1", cpu_limit="2",
        memory_request="1Gi", memory_limit="2Gi",
        max_pods=10, max_services=5, max_secrets=10, max_configmaps=10, max_pvcs=2,
        max_agents=10, max_concurrent_executions=3
    ),
    TenantTier.PROFESSIONAL: TenantQuotas(
        cpu_request="2", cpu_limit="4",
        memory_request="2Gi", memory_limit="4Gi",
        max_pods=20, max_services=10, max_secrets=20, max_configmaps=20, max_pvcs=5,
        max_agents=50, max_concurrent_executions=10
    ),
    TenantTier.ENTERPRISE: TenantQuotas(
        cpu_request="4", cpu_limit="8",
        memory_request="4Gi", memory_limit="8Gi",
        max_pods=50, max_services=20, max_secrets=50, max_configmaps=50, max_pvcs=10,
        max_agents=200, max_concurrent_executions=50
    ),
}


@dataclass
class TenantCredentials:
    """Credentials returned to client after provisioning"""
    tenant_id: str
    api_key: str
    endpoints: Dict[str, str]
    tls_certificate: str
    tls_private_key: str
    ca_certificate: str


@dataclass
class TenantConfig:
    """Tenant configuration for provisioning"""
    tenant_id: str
    organization_name: str
    tier: TenantTier
    license_key: str
    admin_email: str
    created_at: datetime
    expires_at: datetime
    features: Dict[str, bool]


class CertificateAuthority:
    """Manages TLS certificates for tenants"""

    def __init__(self, ca_cert_path: str, ca_key_path: str):
        self.ca_cert_path = ca_cert_path
        self.ca_key_path = ca_key_path
        self._load_ca()

    def _load_ca(self):
        """Load CA certificate and key"""
        # In production, load from HSM or Vault
        if os.path.exists(self.ca_cert_path) and os.path.exists(self.ca_key_path):
            with open(self.ca_cert_path, "rb") as f:
                self.ca_cert = x509.load_pem_x509_certificate(f.read())
            with open(self.ca_key_path, "rb") as f:
                self.ca_key = serialization.load_pem_private_key(f.read(), password=None)
        else:
            # Generate self-signed CA for development
            self._generate_ca()

    def _generate_ca(self):
        """Generate self-signed CA (development only)"""
        logger.warning("Generating self-signed CA - DO NOT USE IN PRODUCTION")

        self.ca_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "AE"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Mirqab Security"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Mirqab Cloud Relay CA"),
        ])

        self.ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self.ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    key_encipherment=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(self.ca_key, hashes.SHA256(), default_backend())
        )

    def generate_tenant_certificate(self, tenant_id: str, dns_names: List[str]) -> tuple:
        """Generate client certificate for tenant"""
        # Generate private key
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        # Build certificate
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "AE"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Mirqab Security"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, f"Tenant: {tenant_id}"),
            x509.NameAttribute(NameOID.COMMON_NAME, tenant_id),
        ])

        # Build SAN extension
        san_list = [x509.DNSName(dns) for dns in dns_names]

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName(san_list),
                critical=False,
            )
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    key_cert_sign=False,
                    crl_sign=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([
                    x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                    x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                ]),
                critical=False,
            )
            .sign(self.ca_key, hashes.SHA256(), default_backend())
        )

        # Serialize to PEM
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        ca_pem = self.ca_cert.public_bytes(serialization.Encoding.PEM).decode()

        return cert_pem, key_pem, ca_pem


class KubernetesProvisioner:
    """Provisions Kubernetes resources for tenants"""

    def __init__(self, kubeconfig_path: Optional[str] = None):
        self.kubeconfig_path = kubeconfig_path or os.environ.get("KUBECONFIG")
        self.base_domain = os.environ.get("BASE_DOMAIN", "relay.mirqab.io")
        self.c2_dns_domain = os.environ.get("C2_DNS_DOMAIN", "c2.mirqab.io")
        self.image_tag = os.environ.get("IMAGE_TAG", "latest")

    def _generate_namespace_manifest(self, config: TenantConfig, quotas: TenantQuotas) -> str:
        """Generate namespace and related resources"""
        namespace = f"tenant-{config.tenant_id}"

        manifests = []

        # Namespace
        manifests.append({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "name": namespace,
                "labels": {
                    "app.kubernetes.io/managed-by": "mirqab-provisioner",
                    "mirqab.io/tenant-id": config.tenant_id,
                    "mirqab.io/tier": config.tier.value,
                    "pod-security.kubernetes.io/enforce": "restricted",
                    "pod-security.kubernetes.io/enforce-version": "latest",
                },
                "annotations": {
                    "mirqab.io/organization": config.organization_name,
                    "mirqab.io/created-at": config.created_at.isoformat(),
                    "mirqab.io/expires-at": config.expires_at.isoformat(),
                }
            }
        })

        # ResourceQuota
        manifests.append({
            "apiVersion": "v1",
            "kind": "ResourceQuota",
            "metadata": {
                "name": "tenant-quota",
                "namespace": namespace,
            },
            "spec": {
                "hard": {
                    "requests.cpu": quotas.cpu_request,
                    "requests.memory": quotas.memory_request,
                    "limits.cpu": quotas.cpu_limit,
                    "limits.memory": quotas.memory_limit,
                    "pods": str(quotas.max_pods),
                    "services": str(quotas.max_services),
                    "secrets": str(quotas.max_secrets),
                    "configmaps": str(quotas.max_configmaps),
                    "persistentvolumeclaims": str(quotas.max_pvcs),
                }
            }
        })

        # LimitRange
        manifests.append({
            "apiVersion": "v1",
            "kind": "LimitRange",
            "metadata": {
                "name": "tenant-limits",
                "namespace": namespace,
            },
            "spec": {
                "limits": [{
                    "type": "Container",
                    "default": {"cpu": "500m", "memory": "512Mi"},
                    "defaultRequest": {"cpu": "100m", "memory": "128Mi"},
                    "max": {"cpu": "2", "memory": "4Gi"},
                    "min": {"cpu": "50m", "memory": "64Mi"},
                }]
            }
        })

        # Default deny NetworkPolicy
        manifests.append({
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name": "default-deny-all",
                "namespace": namespace,
            },
            "spec": {
                "podSelector": {},
                "policyTypes": ["Ingress", "Egress"]
            }
        })

        # Allow DNS egress
        manifests.append({
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name": "allow-dns",
                "namespace": namespace,
            },
            "spec": {
                "podSelector": {},
                "policyTypes": ["Egress"],
                "egress": [{
                    "to": [{
                        "namespaceSelector": {
                            "matchLabels": {"kubernetes.io/metadata.name": "kube-system"}
                        }
                    }],
                    "ports": [
                        {"protocol": "UDP", "port": 53},
                        {"protocol": "TCP", "port": 53}
                    ]
                }]
            }
        })

        # Allow same-namespace traffic
        manifests.append({
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name": "allow-same-namespace",
                "namespace": namespace,
            },
            "spec": {
                "podSelector": {},
                "policyTypes": ["Ingress", "Egress"],
                "ingress": [{"from": [{"podSelector": {}}]}],
                "egress": [{"to": [{"podSelector": {}}]}]
            }
        })

        # Allow C2 ingress from external
        manifests.append({
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name": "allow-c2-ingress",
                "namespace": namespace,
            },
            "spec": {
                "podSelector": {"matchLabels": {"mirqab.io/component": "c2-service"}},
                "policyTypes": ["Ingress"],
                "ingress": [{
                    "from": [],
                    "ports": [
                        {"protocol": "TCP", "port": 443},
                        {"protocol": "TCP", "port": 8443}
                    ]
                }]
            }
        })

        # ServiceAccount
        manifests.append({
            "apiVersion": "v1",
            "kind": "ServiceAccount",
            "metadata": {
                "name": "tenant-workload",
                "namespace": namespace,
            },
            "automountServiceAccountToken": False
        })

        return yaml.dump_all(manifests, default_flow_style=False)

    def _generate_c2_http_manifest(self, config: TenantConfig, api_key: str) -> str:
        """Generate C2 HTTP deployment"""
        namespace = f"tenant-{config.tenant_id}"

        manifests = []

        # Secret for API key
        manifests.append({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": "c2-http-secrets",
                "namespace": namespace,
            },
            "type": "Opaque",
            "stringData": {
                "admin-token": api_key,
            }
        })

        # Deployment
        manifests.append({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": "c2-http",
                "namespace": namespace,
                "labels": {
                    "app": "c2-http",
                    "mirqab.io/tenant-id": config.tenant_id,
                    "mirqab.io/component": "c2-service",
                }
            },
            "spec": {
                "replicas": 2,
                "selector": {
                    "matchLabels": {
                        "app": "c2-http",
                        "mirqab.io/tenant-id": config.tenant_id,
                    }
                },
                "template": {
                    "metadata": {
                        "labels": {
                            "app": "c2-http",
                            "mirqab.io/tenant-id": config.tenant_id,
                            "mirqab.io/component": "c2-service",
                        }
                    },
                    "spec": {
                        "runtimeClassName": "gvisor",
                        "serviceAccountName": "tenant-workload",
                        "securityContext": {
                            "runAsNonRoot": True,
                            "runAsUser": 65534,
                            "runAsGroup": 65534,
                            "fsGroup": 65534,
                            "seccompProfile": {"type": "RuntimeDefault"}
                        },
                        "containers": [{
                            "name": "c2-http",
                            "image": f"ghcr.io/mirqab/cloud-relay/c2-http:{self.image_tag}",
                            "ports": [
                                {"name": "https", "containerPort": 8443},
                                {"name": "metrics", "containerPort": 9090},
                            ],
                            "env": [
                                {"name": "TENANT_ID", "value": config.tenant_id},
                                {"name": "SERVER_PORT", "value": "8443"},
                                {"name": "TLS_ENABLED", "value": "true"},
                                {
                                    "name": "ADMIN_TOKEN",
                                    "valueFrom": {
                                        "secretKeyRef": {
                                            "name": "c2-http-secrets",
                                            "key": "admin-token"
                                        }
                                    }
                                }
                            ],
                            "resources": {
                                "requests": {"cpu": "100m", "memory": "128Mi"},
                                "limits": {"cpu": "500m", "memory": "512Mi"}
                            },
                            "securityContext": {
                                "allowPrivilegeEscalation": False,
                                "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]}
                            },
                            "livenessProbe": {
                                "httpGet": {"path": "/health", "port": 8443, "scheme": "HTTPS"},
                                "initialDelaySeconds": 10,
                                "periodSeconds": 30,
                            },
                            "readinessProbe": {
                                "httpGet": {"path": "/ready", "port": 8443, "scheme": "HTTPS"},
                                "initialDelaySeconds": 5,
                                "periodSeconds": 10,
                            }
                        }]
                    }
                }
            }
        })

        # Service
        manifests.append({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {
                "name": "c2-http",
                "namespace": namespace,
                "annotations": {
                    "external-dns.alpha.kubernetes.io/hostname": f"c2-http.{config.tenant_id}.{self.base_domain}"
                }
            },
            "spec": {
                "type": "ClusterIP",
                "selector": {"app": "c2-http", "mirqab.io/tenant-id": config.tenant_id},
                "ports": [
                    {"name": "https", "port": 443, "targetPort": 8443},
                    {"name": "metrics", "port": 9090, "targetPort": 9090},
                ]
            }
        })

        # Ingress
        manifests.append({
            "apiVersion": "networking.k8s.io/v1",
            "kind": "Ingress",
            "metadata": {
                "name": "c2-http",
                "namespace": namespace,
                "annotations": {
                    "cert-manager.io/cluster-issuer": "letsencrypt-prod",
                    "nginx.ingress.kubernetes.io/ssl-redirect": "true",
                    "nginx.ingress.kubernetes.io/backend-protocol": "HTTPS",
                }
            },
            "spec": {
                "ingressClassName": "nginx",
                "tls": [{
                    "hosts": [f"c2-http.{config.tenant_id}.{self.base_domain}"],
                    "secretName": "c2-http-tls"
                }],
                "rules": [{
                    "host": f"c2-http.{config.tenant_id}.{self.base_domain}",
                    "http": {
                        "paths": [{
                            "path": "/",
                            "pathType": "Prefix",
                            "backend": {
                                "service": {
                                    "name": "c2-http",
                                    "port": {"number": 443}
                                }
                            }
                        }]
                    }
                }]
            }
        })

        return yaml.dump_all(manifests, default_flow_style=False)

    def _generate_c2_dns_manifest(self, config: TenantConfig, api_key: str) -> str:
        """Generate C2 DNS deployment"""
        namespace = f"tenant-{config.tenant_id}"
        dns_subdomain = f"{config.tenant_id}.{self.c2_dns_domain}"

        manifests = []

        # Secret
        manifests.append({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": "c2-dns-secrets",
                "namespace": namespace,
            },
            "type": "Opaque",
            "stringData": {
                "admin-token": api_key,
            }
        })

        # Deployment
        manifests.append({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": "c2-dns",
                "namespace": namespace,
            },
            "spec": {
                "replicas": 2,
                "selector": {
                    "matchLabels": {"app": "c2-dns", "mirqab.io/tenant-id": config.tenant_id}
                },
                "template": {
                    "metadata": {
                        "labels": {
                            "app": "c2-dns",
                            "mirqab.io/tenant-id": config.tenant_id,
                            "mirqab.io/component": "c2-service",
                        }
                    },
                    "spec": {
                        "runtimeClassName": "gvisor",
                        "serviceAccountName": "tenant-workload",
                        "securityContext": {
                            "runAsNonRoot": True,
                            "runAsUser": 65534,
                            "fsGroup": 65534,
                        },
                        "containers": [{
                            "name": "c2-dns",
                            "image": f"ghcr.io/mirqab/cloud-relay/c2-dns:{self.image_tag}",
                            "ports": [
                                {"name": "dns-udp", "containerPort": 5353, "protocol": "UDP"},
                                {"name": "dns-tcp", "containerPort": 5353, "protocol": "TCP"},
                                {"name": "metrics", "containerPort": 9091},
                            ],
                            "env": [
                                {"name": "TENANT_ID", "value": config.tenant_id},
                                {"name": "BASE_DOMAIN", "value": dns_subdomain},
                                {"name": "DNS_PORT", "value": "5353"},
                            ],
                            "resources": {
                                "requests": {"cpu": "50m", "memory": "64Mi"},
                                "limits": {"cpu": "200m", "memory": "256Mi"}
                            },
                            "securityContext": {
                                "allowPrivilegeEscalation": False,
                                "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]}
                            }
                        }]
                    }
                }
            }
        })

        # LoadBalancer Service for DNS
        manifests.append({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {
                "name": "c2-dns",
                "namespace": namespace,
                "annotations": {
                    "external-dns.alpha.kubernetes.io/hostname": dns_subdomain,
                    "service.beta.kubernetes.io/aws-load-balancer-type": "nlb",
                }
            },
            "spec": {
                "type": "LoadBalancer",
                "externalTrafficPolicy": "Local",
                "selector": {"app": "c2-dns", "mirqab.io/tenant-id": config.tenant_id},
                "ports": [
                    {"name": "dns-udp", "port": 53, "targetPort": 5353, "protocol": "UDP"},
                    {"name": "dns-tcp", "port": 53, "targetPort": 5353, "protocol": "TCP"},
                ]
            }
        })

        return yaml.dump_all(manifests, default_flow_style=False)

    def provision_tenant(self, config: TenantConfig) -> Dict[str, str]:
        """Provision all Kubernetes resources for a tenant"""
        quotas = TIER_QUOTAS[config.tier]
        api_key = f"cr_live_{secrets.token_hex(24)}"

        manifests = {
            "namespace": self._generate_namespace_manifest(config, quotas),
            "c2_http": self._generate_c2_http_manifest(config, api_key),
            "c2_dns": self._generate_c2_dns_manifest(config, api_key),
        }

        # In production, apply manifests to cluster
        # kubectl.apply(manifests)

        endpoints = {
            "c2_http": f"https://c2-http.{config.tenant_id}.{self.base_domain}",
            "c2_dns": f"{config.tenant_id}.{self.c2_dns_domain}",
            "payloads": f"https://payloads.{config.tenant_id}.{self.base_domain}",
        }

        return {
            "api_key": api_key,
            "endpoints": endpoints,
            "manifests": manifests,
        }


class TenantProvisioningService:
    """Main service for tenant provisioning"""

    def __init__(self):
        self.ca = CertificateAuthority(
            ca_cert_path=os.environ.get("CA_CERT_PATH", "/etc/mirqab/ca/ca.crt"),
            ca_key_path=os.environ.get("CA_KEY_PATH", "/etc/mirqab/ca/ca.key"),
        )
        self.k8s = KubernetesProvisioner()

    def generate_tenant_id(self, organization_name: str) -> str:
        """Generate unique tenant ID"""
        # Create slug from org name + random suffix
        slug = organization_name.lower()
        slug = "".join(c if c.isalnum() else "-" for c in slug)
        slug = slug[:20].strip("-")
        suffix = secrets.token_hex(4)
        return f"{slug}-{suffix}"

    def provision_tenant(
        self,
        license_key: str,
        organization_name: str,
        tier: TenantTier,
        admin_email: str,
        validity_days: int = 365,
    ) -> TenantCredentials:
        """
        Provision a new tenant in Cloud Relay

        Args:
            license_key: The validated license key
            organization_name: Client organization name
            tier: License tier
            admin_email: Admin contact email
            validity_days: Certificate validity in days

        Returns:
            TenantCredentials with all connection details
        """
        tenant_id = self.generate_tenant_id(organization_name)
        now = datetime.now(timezone.utc)

        config = TenantConfig(
            tenant_id=tenant_id,
            organization_name=organization_name,
            tier=tier,
            license_key=license_key,
            admin_email=admin_email,
            created_at=now,
            expires_at=now + timedelta(days=validity_days),
            features={
                "c2_http": True,
                "c2_dns": tier in [TenantTier.PROFESSIONAL, TenantTier.ENTERPRISE],
                "payload_hosting": True,
                "custom_domains": tier == TenantTier.ENTERPRISE,
            }
        )

        logger.info(f"Provisioning tenant: {tenant_id} ({organization_name})")

        # Provision Kubernetes resources
        k8s_result = self.k8s.provision_tenant(config)

        # Generate TLS certificates
        dns_names = [
            f"c2-http.{tenant_id}.relay.mirqab.io",
            f"{tenant_id}.c2.mirqab.io",
            f"payloads.{tenant_id}.relay.mirqab.io",
            f"*.{tenant_id}.relay.mirqab.io",
        ]
        cert_pem, key_pem, ca_pem = self.ca.generate_tenant_certificate(tenant_id, dns_names)

        logger.info(f"Tenant {tenant_id} provisioned successfully")

        return TenantCredentials(
            tenant_id=tenant_id,
            api_key=k8s_result["api_key"],
            endpoints=k8s_result["endpoints"],
            tls_certificate=cert_pem,
            tls_private_key=key_pem,
            ca_certificate=ca_pem,
        )

    def deprovision_tenant(self, tenant_id: str) -> bool:
        """Remove all tenant resources"""
        logger.info(f"Deprovisioning tenant: {tenant_id}")
        # In production: kubectl delete namespace tenant-{tenant_id}
        return True


# Example usage
if __name__ == "__main__":
    service = TenantProvisioningService()

    # Simulate provisioning
    credentials = service.provision_tenant(
        license_key="MIRQAB-PRO-TEST1234-ABCD",
        organization_name="Acme Corporation",
        tier=TenantTier.PROFESSIONAL,
        admin_email="admin@acme.com",
    )

    print(f"\n=== Tenant Provisioned ===")
    print(f"Tenant ID: {credentials.tenant_id}")
    print(f"API Key: {credentials.api_key}")
    print(f"Endpoints: {json.dumps(credentials.endpoints, indent=2)}")
    print(f"TLS Certificate: {credentials.tls_certificate[:100]}...")
