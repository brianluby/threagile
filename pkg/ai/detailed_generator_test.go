package ai

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/threagile/threagile/pkg/types"
)

func TestDetailedGenerator_Generate(t *testing.T) {
	generator := NewDetailedGenerator()

	tests := []struct {
		name    string
		results []*ParseResult
		options GeneratorOptions
		check   func(t *testing.T, model *types.Model)
	}{
		{
			name: "Enhanced security configurations",
			results: []*ParseResult{
				{
					SecurityGroups: map[string]*SecurityGroup{
						"sg-web": {
							ID:          "sg-web",
							Name:        "web-security-group",
							Description: "Security group for web servers",
							Rules: []SecurityRule{
								{
									Direction: "ingress",
									Protocol:  "tcp",
									Port:      "80",
									Source:    "0.0.0.0/0",
								},
							},
						},
					},
					Resources: map[string]*Resource{
						"web-server": {
							ID:   "web-server",
							Name: "WebServer",
							Type: "ec2",
						},
					},
				},
			},
			options: GeneratorOptions{
				Mode: ModeDetailed,
			},
			check: func(t *testing.T, model *types.Model) {
				assert.NotNil(t, model)
				assert.NotEmpty(t, model.RiskTracking)
				// Should identify overly permissive rule
				hasOverlyPermissive := false
				for _, risk := range model.RiskTracking {
					if risk.Justification == "Security risk: overly-permissive" {
						hasOverlyPermissive = true
						break
					}
				}
				assert.True(t, hasOverlyPermissive, "Should identify overly permissive security group")
			},
		},
		{
			name: "Network segmentation and trust boundaries",
			results: []*ParseResult{
				{
					Networks: map[string]*Network{
						"vpc-main": {
							ID:       "vpc-main",
							Name:     "Main VPC",
							Type:     "vpc",
							Provider: "aws",
						},
						"subnet-public": {
							ID:       "subnet-public",
							Name:     "Public Subnet",
							Type:     "subnet",
							Provider: "aws",
						},
						"subnet-private": {
							ID:       "subnet-private",
							Name:     "Private Subnet",
							Type:     "subnet",
							Provider: "aws",
						},
					},
				},
			},
			options: GeneratorOptions{
				Mode: ModeDetailed,
			},
			check: func(t *testing.T, model *types.Model) {
				assert.NotNil(t, model)
				assert.NotEmpty(t, model.TrustBoundaries)
				// Should create network boundaries
				hasNetworkBoundary := false
				for _, boundary := range model.TrustBoundaries {
					if boundary.Type == "network-cloud-provider" {
						hasNetworkBoundary = true
						// Check for zone tagging
						hasZoneTag := false
						for _, tag := range boundary.Tags {
							if tag == "zone:public" || tag == "zone:private" {
								hasZoneTag = true
								break
							}
						}
						assert.True(t, hasZoneTag, "Boundary should have zone tag")
						break
					}
				}
				assert.True(t, hasNetworkBoundary, "Should create network trust boundaries")
			},
		},
		{
			name: "IAM analysis with excessive permissions",
			results: []*ParseResult{
				{
					Roles: map[string]*Role{
						"admin-role": {
							ID:          "admin-role",
							Name:        "AdminRole",
							Description: "Role with * permissions",
						},
					},
					Policies: map[string]*Policy{
						"full-access": {
							ID:          "full-access",
							Name:        "FullAccessPolicy",
							Description: "Policy with wildcard * access",
						},
					},
				},
			},
			options: GeneratorOptions{
				Mode: ModeDetailed,
			},
			check: func(t *testing.T, model *types.Model) {
				assert.NotNil(t, model)
				assert.NotEmpty(t, model.RiskTracking)
				// Should identify excessive permissions
				hasExcessivePerms := false
				hasWildcardPerms := false
				for _, risk := range model.RiskTracking {
					if risk.Justification == "IAM risk: excessive-permissions" {
						hasExcessivePerms = true
					}
					if risk.Justification == "IAM risk: wildcard-permissions" {
						hasWildcardPerms = true
					}
				}
				assert.True(t, hasExcessivePerms, "Should identify excessive permissions")
				assert.True(t, hasWildcardPerms, "Should identify wildcard permissions")
			},
		},
		{
			name: "Data classification and flow analysis",
			results: []*ParseResult{
				{
					Databases: map[string]*Database{
						"user-db": {
							ID:   "user-db",
							Name: "UserDatabase",
							Type: "relational",
						},
						"payment-db": {
							ID:   "payment-db",
							Name: "PaymentDatabase",
							Type: "relational",
						},
						"cache-db": {
							ID:   "cache-db",
							Name: "CacheDatabase",
							Type: "cache",
						},
					},
				},
			},
			options: GeneratorOptions{
				Mode: ModeDetailed,
			},
			check: func(t *testing.T, model *types.Model) {
				assert.NotNil(t, model)
				assert.NotEmpty(t, model.DataAssets)
				
				// Check data classification
				hasConfidential := false
				hasRestricted := false
				for _, dataAsset := range model.DataAssets {
					for _, tag := range dataAsset.Tags {
						if tag == "classification:confidential" {
							hasConfidential = true
						}
						if tag == "classification:restricted" {
							hasRestricted = true
						}
					}
				}
				assert.True(t, hasConfidential, "Should classify user data as confidential")
				assert.True(t, hasRestricted, "Should classify payment data as restricted")
			},
		},
		{
			name: "Encryption analysis",
			results: []*ParseResult{
				{
					Storages: map[string]*Storage{
						"public-bucket": {
							ID:   "public-bucket",
							Name: "PublicBucket",
							Type: "object",
							Tags: map[string]string{
								"public": "true",
							},
						},
						"private-bucket": {
							ID:   "private-bucket",
							Name: "PrivateBucket",
							Type: "object",
							Tags: map[string]string{
								"encrypted": "false",
							},
						},
					},
				},
			},
			options: GeneratorOptions{
				Mode: ModeDetailed,
			},
			check: func(t *testing.T, model *types.Model) {
				assert.NotNil(t, model)
				assert.NotEmpty(t, model.RiskTracking)
				
				// Should identify public access and missing encryption
				hasPublicAccess := false
				hasUnencrypted := false
				for _, risk := range model.RiskTracking {
					if risk.Justification == "Storage risk: public-access" {
						hasPublicAccess = true
					}
					if risk.Justification == "Storage risk: unencrypted-storage" {
						hasUnencrypted = true
					}
				}
				assert.True(t, hasPublicAccess, "Should identify public storage access")
				assert.True(t, hasUnencrypted, "Should identify unencrypted storage")
			},
		},
		{
			name: "Compliance pattern detection",
			results: []*ParseResult{
				{
					Databases: map[string]*Database{
						"payment-processor": {
							ID:   "payment-processor",
							Name: "PaymentProcessor",
							Type: "relational",
						},
						"patient-records": {
							ID:   "patient-records",
							Name: "PatientRecords",
							Type: "relational",
						},
						"customer-data": {
							ID:   "customer-data",
							Name: "CustomerData",
							Type: "relational",
						},
					},
				},
			},
			options: GeneratorOptions{
				Mode: ModeDetailed,
			},
			check: func(t *testing.T, model *types.Model) {
				assert.NotNil(t, model)
				
				// Should add compliance tags
				hasPCITag := false
				hasHIPAATag := false
				hasGDPRTag := false
				
				for _, asset := range model.TechnicalAssets {
					for _, tag := range asset.Tags {
						if tag == "compliance:pci-dss" {
							hasPCITag = true
						}
						if tag == "compliance:hipaa" {
							hasHIPAATag = true
						}
						if tag == "compliance:gdpr" {
							hasGDPRTag = true
						}
					}
				}
				
				assert.True(t, hasPCITag, "Should detect PCI compliance pattern")
				assert.True(t, hasHIPAATag, "Should detect HIPAA compliance pattern")
				assert.True(t, hasGDPRTag, "Should detect GDPR compliance pattern")
			},
		},
		{
			name: "Business criticality determination",
			results: []*ParseResult{
				{
					Resources: map[string]*Resource{
						"r1": {ID: "r1", Name: "Resource1"},
						"r2": {ID: "r2", Name: "Resource2"},
						"r3": {ID: "r3", Name: "Resource3"},
					},
					Databases: map[string]*Database{
						"db1": {ID: "db1", Name: "Database1"},
						"db2": {ID: "db2", Name: "Database2"},
						"db3": {ID: "db3", Name: "Database3"},
						"db4": {ID: "db4", Name: "Database4"},
						"db5": {ID: "db5", Name: "Database5"},
						"db6": {ID: "db6", Name: "Database6"},
					},
				},
			},
			options: GeneratorOptions{
				Mode: ModeDetailed,
			},
			check: func(t *testing.T, model *types.Model) {
				assert.NotNil(t, model)
				assert.NotNil(t, model.Overview)
				// With 6 databases, should be marked as critical
				assert.Equal(t, "critical", model.Overview.BusinessCriticality)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			model, err := generator.Generate(tt.results, tt.options)
			require.NoError(t, err)
			tt.check(t, model)
		})
	}
}

func TestDetailedGenerator_NetworkZoneDetermination(t *testing.T) {
	generator := NewDetailedGenerator()

	tests := []struct {
		name     string
		network  *Network
		wantZone string
	}{
		{
			name: "Public network",
			network: &Network{
				ID:   "subnet-1",
				Name: "Public Subnet",
			},
			wantZone: "public",
		},
		{
			name: "DMZ network",
			network: &Network{
				ID:   "subnet-2",
				Name: "DMZ Subnet",
			},
			wantZone: "dmz",
		},
		{
			name: "Private network",
			network: &Network{
				ID:   "subnet-3",
				Name: "Private Subnet",
			},
			wantZone: "private",
		},
		{
			name: "Default to private",
			network: &Network{
				ID:   "subnet-4",
				Name: "Application Subnet",
			},
			wantZone: "private",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			zone := generator.determineNetworkZone(tt.network)
			assert.Equal(t, tt.wantZone, zone)
		})
	}
}

func TestDetailedGenerator_DataClassification(t *testing.T) {
	generator := NewDetailedGenerator()

	tests := []struct {
		name               string
		database           *Database
		wantClassification string
	}{
		{
			name: "User database",
			database: &Database{
				ID:   "db-1",
				Name: "UserDatabase",
			},
			wantClassification: "confidential",
		},
		{
			name: "Payment database",
			database: &Database{
				ID:   "db-2",
				Name: "PaymentProcessor",
			},
			wantClassification: "restricted",
		},
		{
			name: "Public database",
			database: &Database{
				ID:   "db-3",
				Name: "PublicContent",
			},
			wantClassification: "public",
		},
		{
			name: "Cache database",
			database: &Database{
				ID:   "db-4",
				Name: "SessionCache",
			},
			wantClassification: "public",
		},
		{
			name: "Default to internal",
			database: &Database{
				ID:   "db-5",
				Name: "ApplicationDB",
			},
			wantClassification: "internal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			classification := generator.determineDataClassification(tt.database)
			assert.Equal(t, tt.wantClassification, classification)
		})
	}
}

func TestDetailedGenerator_CompliancePatternDetection(t *testing.T) {
	generator := NewDetailedGenerator()

	tests := []struct {
		name         string
		result       *ParseResult
		wantPatterns []string
	}{
		{
			name: "PCI pattern",
			result: &ParseResult{
				Databases: map[string]*Database{
					"payment-db": {
						ID:   "payment-db",
						Name: "PaymentProcessor",
					},
				},
			},
			wantPatterns: []string{"pci-dss"},
		},
		{
			name: "HIPAA pattern",
			result: &ParseResult{
				Databases: map[string]*Database{
					"patient-db": {
						ID:   "patient-db",
						Name: "PatientRecords",
					},
				},
			},
			wantPatterns: []string{"hipaa"},
		},
		{
			name: "GDPR pattern",
			result: &ParseResult{
				Databases: map[string]*Database{
					"user-db": {
						ID:   "user-db",
						Name: "UserProfiles",
					},
				},
			},
			wantPatterns: []string{"gdpr"},
		},
		{
			name: "Multiple patterns",
			result: &ParseResult{
				Databases: map[string]*Database{
					"payment-db": {
						ID:   "payment-db",
						Name: "PaymentData",
					},
					"user-db": {
						ID:   "user-db",
						Name: "CustomerData",
					},
				},
			},
			wantPatterns: []string{"pci-dss", "gdpr"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			patterns := generator.detectCompliancePatterns(tt.result)
			for _, wantPattern := range tt.wantPatterns {
				assert.Contains(t, patterns, wantPattern)
			}
		})
	}
}

func TestDetailedGenerator_BusinessCriticalityDetermination(t *testing.T) {
	generator := NewDetailedGenerator()

	tests := []struct {
		name      string
		counts    map[string]int
		wantLevel string
	}{
		{
			name: "Critical - many resources",
			counts: map[string]int{
				"resources": 30,
				"databases": 10,
			},
			wantLevel: "critical",
		},
		{
			name: "Critical - many databases",
			counts: map[string]int{
				"resources": 10,
				"databases": 6,
			},
			wantLevel: "critical",
		},
		{
			name: "Important",
			counts: map[string]int{
				"resources": 15,
				"databases": 3,
			},
			wantLevel: "important",
		},
		{
			name: "Internal",
			counts: map[string]int{
				"resources": 5,
				"databases": 1,
			},
			wantLevel: "internal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			level := generator.determineBusinessCriticality(tt.counts)
			assert.Equal(t, tt.wantLevel, level)
		})
	}
}