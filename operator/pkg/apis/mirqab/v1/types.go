// Mirqab Cloud Relay - Tenant API Types
package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// TenantTier defines the subscription tier
type TenantTier string

const (
	TierTrial        TenantTier = "trial"
	TierPOC          TenantTier = "poc"
	TierStarter      TenantTier = "starter"
	TierProfessional TenantTier = "professional"
	TierEnterprise   TenantTier = "enterprise"
)

// TenantPhase defines the current phase of tenant lifecycle
type TenantPhase string

const (
	PhasePending      TenantPhase = "Pending"
	PhaseProvisioning TenantPhase = "Provisioning"
	PhaseActive       TenantPhase = "Active"
	PhaseSuspended    TenantPhase = "Suspended"
	PhaseTerminating  TenantPhase = "Terminating"
	PhaseFailed       TenantPhase = "Failed"
)

// ConditionType defines condition types for tenant status
type ConditionType string

const (
	ConditionLicenseValid      ConditionType = "LicenseValid"
	ConditionNamespaceReady    ConditionType = "NamespaceReady"
	ConditionC2HttpReady       ConditionType = "C2HttpReady"
	ConditionC2DnsReady        ConditionType = "C2DnsReady"
	ConditionPayloadReady      ConditionType = "PayloadServerReady"
	ConditionCertificatesReady ConditionType = "CertificatesIssued"
	ConditionReady             ConditionType = "Ready"
)

// TenantFeatures defines feature flags for a tenant
type TenantFeatures struct {
	// +optional
	C2Http bool `json:"c2Http,omitempty"`
	// +optional
	C2Dns bool `json:"c2Dns,omitempty"`
	// +optional
	C2Smb bool `json:"c2Smb,omitempty"`
	// +optional
	PayloadHosting bool `json:"payloadHosting,omitempty"`
	// +optional
	CustomDomains bool `json:"customDomains,omitempty"`
}

// ResourceOverrides allows enterprise tenants to override defaults
type ResourceOverrides struct {
	// +optional
	MaxPods int `json:"maxPods,omitempty"`
	// +optional
	CPULimit string `json:"cpuLimit,omitempty"`
	// +optional
	MemoryLimit string `json:"memoryLimit,omitempty"`
}

// TenantSpec defines the desired state of Tenant
type TenantSpec struct {
	// LicenseKey is the valid Mirqab license key
	// +kubebuilder:validation:Pattern=`^MIRQAB-[A-Z]{3}-[A-Z0-9]{8}-[A-Z0-9]{12}$`
	LicenseKey string `json:"licenseKey"`

	// OrganizationName is the customer organization name
	// +kubebuilder:validation:MinLength=2
	// +kubebuilder:validation:MaxLength=100
	OrganizationName string `json:"organizationName"`

	// Tier is the subscription tier
	// +kubebuilder:validation:Enum=trial;poc;starter;professional;enterprise
	Tier TenantTier `json:"tier"`

	// AdminEmail is the admin contact email
	AdminEmail string `json:"adminEmail"`

	// Features defines enabled features for this tenant
	// +optional
	Features TenantFeatures `json:"features,omitempty"`

	// CustomDomains for C2 endpoints (enterprise only)
	// +optional
	CustomDomains []string `json:"customDomains,omitempty"`

	// ResourceOverrides for enterprise tenants
	// +optional
	ResourceOverrides *ResourceOverrides `json:"resourceOverrides,omitempty"`
}

// TenantEndpoints contains service endpoints
type TenantEndpoints struct {
	// +optional
	C2Http string `json:"c2Http,omitempty"`
	// +optional
	C2Dns string `json:"c2Dns,omitempty"`
	// +optional
	Payloads string `json:"payloads,omitempty"`
	// +optional
	Admin string `json:"admin,omitempty"`
}

// TenantCondition describes the state of a tenant condition
type TenantCondition struct {
	// Type of condition
	Type ConditionType `json:"type"`
	// Status of the condition (True, False, Unknown)
	Status metav1.ConditionStatus `json:"status"`
	// LastTransitionTime is the time the condition transitioned
	LastTransitionTime metav1.Time `json:"lastTransitionTime"`
	// Reason is a machine-readable reason for the condition
	// +optional
	Reason string `json:"reason,omitempty"`
	// Message is a human-readable message
	// +optional
	Message string `json:"message,omitempty"`
}

// TenantStatus defines the observed state of Tenant
type TenantStatus struct {
	// Phase is the current lifecycle phase
	// +optional
	Phase TenantPhase `json:"phase,omitempty"`

	// Conditions provide detailed status information
	// +optional
	Conditions []TenantCondition `json:"conditions,omitempty"`

	// TenantID is the generated tenant identifier
	// +optional
	TenantID string `json:"tenantId,omitempty"`

	// Namespace is the tenant's Kubernetes namespace
	// +optional
	Namespace string `json:"namespace,omitempty"`

	// Endpoints contains service URLs
	// +optional
	Endpoints TenantEndpoints `json:"endpoints,omitempty"`

	// APIKey reference (stored in Secret)
	// +optional
	APIKey string `json:"apiKey,omitempty"`

	// CertificateSecretRef is the name of the Secret containing TLS certs
	// +optional
	CertificateSecretRef string `json:"certificateSecretRef,omitempty"`

	// ActiveChannels is the number of active C2 channels
	// +optional
	ActiveChannels int `json:"activeChannels,omitempty"`

	// StorageUsedBytes is the payload storage used
	// +optional
	StorageUsedBytes int64 `json:"storageUsedBytes,omitempty"`

	// LicenseExpiresAt is the license expiration date
	// +optional
	LicenseExpiresAt *metav1.Time `json:"licenseExpiresAt,omitempty"`

	// LastHealthCheck timestamp
	// +optional
	LastHealthCheck *metav1.Time `json:"lastHealthCheck,omitempty"`

	// ObservedGeneration for change detection
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=mrt
// +kubebuilder:printcolumn:name="Tier",type=string,JSONPath=`.spec.tier`
// +kubebuilder:printcolumn:name="Organization",type=string,JSONPath=`.spec.organizationName`
// +kubebuilder:printcolumn:name="Status",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Channels",type=integer,JSONPath=`.status.activeChannels`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// Tenant is the Schema for the tenants API
type Tenant struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   TenantSpec   `json:"spec,omitempty"`
	Status TenantStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// TenantList contains a list of Tenant
type TenantList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Tenant `json:"items"`
}

// GetCondition returns the condition with the given type
func (t *Tenant) GetCondition(condType ConditionType) *TenantCondition {
	for i := range t.Status.Conditions {
		if t.Status.Conditions[i].Type == condType {
			return &t.Status.Conditions[i]
		}
	}
	return nil
}

// SetCondition sets or updates a condition
func (t *Tenant) SetCondition(cond TenantCondition) {
	for i := range t.Status.Conditions {
		if t.Status.Conditions[i].Type == cond.Type {
			t.Status.Conditions[i] = cond
			return
		}
	}
	t.Status.Conditions = append(t.Status.Conditions, cond)
}

// IsReady returns true if the tenant is fully ready
func (t *Tenant) IsReady() bool {
	cond := t.GetCondition(ConditionReady)
	return cond != nil && cond.Status == metav1.ConditionTrue
}

// TierQuotas returns resource quotas for a tier
func TierQuotas(tier TenantTier) (cpuLimit, memLimit string, maxPods int) {
	switch tier {
	case TierTrial:
		return "1", "1Gi", 5
	case TierPOC:
		return "2", "2Gi", 15
	case TierStarter:
		return "2", "2Gi", 10
	case TierProfessional:
		return "4", "4Gi", 20
	case TierEnterprise:
		return "8", "8Gi", 50
	default:
		return "1", "1Gi", 5
	}
}

// TierChannelLimit returns max C2 channels for a tier
func TierChannelLimit(tier TenantTier) int {
	switch tier {
	case TierTrial:
		return 2
	case TierPOC:
		return 10
	case TierStarter:
		return 5
	case TierProfessional:
		return 20
	case TierEnterprise:
		return 100
	default:
		return 2
	}
}

// TierStorageLimit returns max storage in bytes for a tier
func TierStorageLimit(tier TenantTier) int64 {
	switch tier {
	case TierTrial:
		return 1 * 1024 * 1024 * 1024 // 1 GB
	case TierPOC:
		return 25 * 1024 * 1024 * 1024 // 25 GB
	case TierStarter:
		return 10 * 1024 * 1024 * 1024 // 10 GB
	case TierProfessional:
		return 50 * 1024 * 1024 * 1024 // 50 GB
	case TierEnterprise:
		return 500 * 1024 * 1024 * 1024 // 500 GB
	default:
		return 1 * 1024 * 1024 * 1024
	}
}

// TierValidityDays returns license validity in days
func TierValidityDays(tier TenantTier) int {
	switch tier {
	case TierTrial:
		return 14
	case TierPOC:
		return 180
	case TierStarter, TierProfessional, TierEnterprise:
		return 365
	default:
		return 14
	}
}

var (
	// SchemeGroupVersion is group version used to register these objects
	SchemeGroupVersion = schema.GroupVersion{Group: "mirqab.io", Version: "v1"}

	// SchemeBuilder is used to add go types to the GroupVersionKind scheme
	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)

	// AddToScheme adds the types in this group-version to the given scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)

func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(SchemeGroupVersion,
		&Tenant{},
		&TenantList{},
	)
	metav1.AddToGroupVersion(scheme, SchemeGroupVersion)
	return nil
}
