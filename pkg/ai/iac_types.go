package ai

import (
	"fmt"
	"github.com/threagile/threagile/pkg/types"
)

// IaC Parser Result Types
// These types are used by IaC parsers to return discovered infrastructure

// ParseResult contains infrastructure components discovered by IaC parsers
type ParseResult struct {
	Resources      map[string]*Resource      `json:"resources,omitempty"`
	Networks       map[string]*Network       `json:"networks,omitempty"`
	SecurityGroups map[string]*SecurityGroup `json:"security_groups,omitempty"`
	Databases      map[string]*Database      `json:"databases,omitempty"`
	Storages       map[string]*Storage       `json:"storages,omitempty"`
	LoadBalancers  map[string]*LoadBalancer  `json:"load_balancers,omitempty"`
	Containers     map[string]*Container     `json:"containers,omitempty"`
	Functions      map[string]*Function      `json:"functions,omitempty"`
	Queues         map[string]*Queue         `json:"queues,omitempty"`
	Topics         map[string]*Topic         `json:"topics,omitempty"`
	Users          map[string]*User          `json:"users,omitempty"`
	Roles          map[string]*Role          `json:"roles,omitempty"`
	Policies       map[string]*Policy        `json:"policies,omitempty"`
	Metadata       Metadata                  `json:"metadata,omitempty"`
}

// Resource represents a generic infrastructure resource
type Resource struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Type     string            `json:"type"`
	Provider string            `json:"provider"`
	Tags     map[string]string `json:"tags,omitempty"`
}

// Network represents a network or subnet
type Network struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Type     string            `json:"type"` // vpc, subnet, etc.
	Provider string            `json:"provider"`
	CIDR     string            `json:"cidr,omitempty"`
	Tags     map[string]string `json:"tags,omitempty"`
}

// SecurityGroup represents a security group or firewall rules
type SecurityGroup struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Rules       []SecurityRule    `json:"rules,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
}

// SecurityRule represents a security group rule
type SecurityRule struct {
	Direction string `json:"direction"` // ingress, egress
	Protocol  string `json:"protocol"`
	Port      string `json:"port,omitempty"`
	Source    string `json:"source,omitempty"`
	Target    string `json:"target,omitempty"`
}

// Database represents a database instance
type Database struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Type     string            `json:"type"` // relational, nosql, cache
	Engine   string            `json:"engine,omitempty"`
	Provider string            `json:"provider"`
	Tags     map[string]string `json:"tags,omitempty"`
}

// Storage represents a storage resource
type Storage struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Type     string            `json:"type"` // object, file, block
	Provider string            `json:"provider"`
	Tags     map[string]string `json:"tags,omitempty"`
}

// LoadBalancer represents a load balancer
type LoadBalancer struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Type     string            `json:"type"` // application, network, classic
	Provider string            `json:"provider"`
	Tags     map[string]string `json:"tags,omitempty"`
}

// Container represents a container or container service
type Container struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Image    string            `json:"image,omitempty"`
	Provider string            `json:"provider"`
	Tags     map[string]string `json:"tags,omitempty"`
}

// Function represents a serverless function
type Function struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Runtime  string            `json:"runtime,omitempty"`
	Handler  string            `json:"handler,omitempty"`
	Provider string            `json:"provider"`
	Tags     map[string]string `json:"tags,omitempty"`
}

// Queue represents a message queue
type Queue struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Provider string            `json:"provider"`
	Tags     map[string]string `json:"tags,omitempty"`
}

// Topic represents a pub/sub topic
type Topic struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Provider string            `json:"provider"`
	Tags     map[string]string `json:"tags,omitempty"`
}

// User represents an IAM user
type User struct {
	ID   string            `json:"id"`
	Name string            `json:"name"`
	Tags map[string]string `json:"tags,omitempty"`
}

// Role represents an IAM role
type Role struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
}

// Policy represents an IAM policy
type Policy struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Document    string            `json:"document,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
}

// Metadata contains additional information about the parsed infrastructure
type Metadata struct {
	SourceFile         string                 `json:"source_file,omitempty"`
	IaCType            string                 `json:"iac_type,omitempty"`
	Parameters         map[string]interface{} `json:"parameters,omitempty"`
	Outputs            map[string]interface{} `json:"outputs,omitempty"`
	Variables          map[string]interface{} `json:"variables,omitempty"`
	DataSources        map[string]interface{} `json:"data_sources,omitempty"`
	Modules            map[string]interface{} `json:"modules,omitempty"`
	SensitiveVariables interface{}            `json:"sensitive_variables,omitempty"`
	SensitiveOutputs   interface{}            `json:"sensitive_outputs,omitempty"`
	PartialParse       bool                   `json:"partial_parse,omitempty"`
}

// IaCParser interface for Infrastructure as Code parsers
type IaCParser interface {
	// SupportsFile checks if the parser supports the given file
	SupportsFile(filename string) bool
	
	// ParseFile parses a file and returns infrastructure components
	ParseFile(filename string, content []byte) (*ParseResult, error)
	
	// ToThreagileModel converts parsed infrastructure to Threagile model
	ToThreagileModel(result *ParseResult) (*types.Model, error)
}

// ParserRegistry manages IaC parsers
type ParserRegistry struct {
	parsers map[string]IaCParser
}

// NewParserRegistry creates a new parser registry
func NewParserRegistry() *ParserRegistry {
	return &ParserRegistry{
		parsers: make(map[string]IaCParser),
	}
}

// Register adds a parser to the registry
func (r *ParserRegistry) Register(name string, parser IaCParser) error {
	if _, exists := r.parsers[name]; exists {
		return fmt.Errorf("parser %s already registered", name)
	}
	r.parsers[name] = parser
	return nil
}

// GetParser returns a parser by name
func (r *ParserRegistry) GetParser(name string) (IaCParser, bool) {
	parser, exists := r.parsers[name]
	return parser, exists
}

// GetParserForFile returns the appropriate parser for a file
func (r *ParserRegistry) GetParserForFile(filename string) (IaCParser, bool) {
	for _, parser := range r.parsers {
		if parser.SupportsFile(filename) {
			return parser, true
		}
	}
	return nil, false
}