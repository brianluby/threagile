package hcl

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParser_SupportsFile(t *testing.T) {
	parser := NewParser()

	tests := []struct {
		name     string
		filename string
		want     bool
	}{
		{
			name:     "terraform file",
			filename: "main.tf",
			want:     true,
		},
		{
			name:     "hcl file",
			filename: "config.hcl",
			want:     true,
		},
		{
			name:     "terraform json file",
			filename: "main.tf.json",
			want:     true,
		},
		{
			name:     "non-terraform file",
			filename: "main.go",
			want:     false,
		},
		{
			name:     "yaml file",
			filename: "config.yaml",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parser.SupportsFile(tt.filename)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParser_ParseFile(t *testing.T) {
	parser := NewParser()

	tests := []struct {
		name    string
		content string
		wantErr bool
		check   func(t *testing.T, result interface{})
	}{
		{
			name: "basic AWS resources",
			content: `
resource "aws_instance" "web" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"
  
  tags = {
    Name = "WebServer"
  }
}

resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
  
  tags = {
    Environment = "Production"
  }
}

resource "aws_security_group" "web_sg" {
  name        = "web_security_group"
  description = "Security group for web servers"
  
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
`,
			wantErr: false,
			check: func(t *testing.T, result interface{}) {
				res := result.(map[string]interface{})
				// Check that resources were parsed
				assert.NotNil(t, res["Resources"])
				assert.NotNil(t, res["Storages"])
				assert.NotNil(t, res["SecurityGroups"])
			},
		},
		{
			name: "RDS database",
			content: `
resource "aws_rds_cluster" "postgresql" {
  cluster_identifier      = "aurora-cluster-demo"
  engine                  = "aurora-postgresql"
  engine_version          = "13.6"
  database_name           = "mydb"
  master_username         = "foo"
  master_password         = "mustbeeightcharacters"
  backup_retention_period = 5
  preferred_backup_window = "07:00-09:00"
}
`,
			wantErr: false,
			check: func(t *testing.T, result interface{}) {
				res := result.(map[string]interface{})
				assert.NotNil(t, res["Databases"])
			},
		},
		{
			name: "Lambda function",
			content: `
resource "aws_lambda_function" "test_lambda" {
  filename      = "lambda_function_payload.zip"
  function_name = "lambda_function_name"
  role          = aws_iam_role.iam_for_lambda.arn
  handler       = "index.test"
  runtime       = "nodejs14.x"
  
  environment {
    variables = {
      foo = "bar"
    }
  }
}
`,
			wantErr: false,
			check: func(t *testing.T, result interface{}) {
				res := result.(map[string]interface{})
				assert.NotNil(t, res["Functions"])
			},
		},
		{
			name: "VPC and subnets",
			content: `
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
  
  tags = {
    Name = "main"
  }
}

resource "aws_subnet" "public" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "us-west-2a"
  
  tags = {
    Name = "Public Subnet"
  }
}

resource "aws_subnet" "private" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "us-west-2b"
  
  tags = {
    Name = "Private Subnet"
  }
}
`,
			wantErr: false,
			check: func(t *testing.T, result interface{}) {
				res := result.(map[string]interface{})
				assert.NotNil(t, res["Networks"])
			},
		},
		{
			name: "IAM resources",
			content: `
resource "aws_iam_user" "lb" {
  name = "loadbalancer"
  path = "/system/"
  
  tags = {
    tag-key = "tag-value"
  }
}

resource "aws_iam_role" "test_role" {
  name = "test_role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })
}

resource "aws_iam_policy" "policy" {
  name        = "test_policy"
  path        = "/"
  description = "My test policy"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "ec2:Describe*",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}
`,
			wantErr: false,
			check: func(t *testing.T, result interface{}) {
				res := result.(map[string]interface{})
				assert.NotNil(t, res["Users"])
				assert.NotNil(t, res["Roles"])
				assert.NotNil(t, res["Policies"])
			},
		},
		{
			name: "Load balancer",
			content: `
resource "aws_lb" "test" {
  name               = "test-lb-tf"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.lb_sg.id]
  subnets            = [for subnet in aws_subnet.public : subnet.id]
  
  enable_deletion_protection = true
  
  tags = {
    Environment = "production"
  }
}
`,
			wantErr: false,
			check: func(t *testing.T, result interface{}) {
				res := result.(map[string]interface{})
				assert.NotNil(t, res["LoadBalancers"])
			},
		},
		{
			name: "Variables and outputs",
			content: `
variable "instance_type" {
  description = "Type of EC2 instance"
  type        = string
  default     = "t2.micro"
}

variable "db_password" {
  description = "Password for the database"
  type        = string
  sensitive   = true
}

output "instance_ip" {
  value = aws_instance.web.public_ip
}

output "db_connection_string" {
  value     = "postgresql://${aws_rds_cluster.postgresql.endpoint}"
  sensitive = true
}
`,
			wantErr: false,
			check: func(t *testing.T, result interface{}) {
				res := result.(map[string]interface{})
				metadata := res["Metadata"].(map[string]interface{})
				assert.NotNil(t, metadata)
				// Check for sensitive variables/outputs tracking
			},
		},
		{
			name:    "invalid HCL",
			content: `This is not valid HCL { broken syntax`,
			wantErr: true,
			check:   func(t *testing.T, result interface{}) {},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parser.ParseFile("test.tf", []byte(tt.content))
			
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			
			require.NoError(t, err)
			require.NotNil(t, result)
			
			// Convert result to map for easier checking
			resultMap := map[string]interface{}{
				"Resources":      result.Resources,
				"Networks":       result.Networks,
				"SecurityGroups": result.SecurityGroups,
				"Databases":      result.Databases,
				"Storages":       result.Storages,
				"LoadBalancers":  result.LoadBalancers,
				"Functions":      result.Functions,
				"Users":          result.Users,
				"Roles":          result.Roles,
				"Policies":       result.Policies,
				"Metadata":       result.Metadata,
			}
			
			tt.check(t, resultMap)
		})
	}
}

func TestParser_ToThreagileModel(t *testing.T) {
	parser := NewParser()
	
	// Parse a sample Terraform file
	content := `
resource "aws_instance" "web" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"
}

resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
}

resource "aws_rds_instance" "database" {
  identifier     = "mydb"
  engine         = "postgres"
  instance_class = "db.t3.micro"
}

resource "aws_lb" "main" {
  name = "main-lb"
}

resource "aws_lambda_function" "processor" {
  function_name = "data-processor"
  runtime       = "python3.9"
}
`
	
	result, err := parser.ParseFile("test.tf", []byte(content))
	require.NoError(t, err)
	
	// Convert to Threagile model
	model, err := parser.ToThreagileModel(result)
	require.NoError(t, err)
	require.NotNil(t, model)
	
	// Check that assets were created
	assert.NotEmpty(t, model.TechnicalAssets)
	
	// Check specific asset types
	hasCompute := false
	hasDatastore := false
	hasLoadBalancer := false
	
	for _, asset := range model.TechnicalAssets {
		switch asset.Type {
		case "process":
			hasCompute = true
		case "datastore":
			hasDatastore = true
		case "load-balancer":
			hasLoadBalancer = true
		}
	}
	
	assert.True(t, hasCompute, "Should have compute resources")
	assert.True(t, hasDatastore, "Should have datastore resources")
	assert.True(t, hasLoadBalancer, "Should have load balancer resources")
}

func TestParser_ProviderDetection(t *testing.T) {
	parser := NewParser()
	
	tests := []struct {
		name         string
		resourceType string
		wantProvider string
	}{
		{"AWS resource", "aws_instance", "aws"},
		{"GCP resource", "google_compute_instance", "gcp"},
		{"Azure resource", "azurerm_virtual_machine", "azure"},
		{"Kubernetes resource", "kubernetes_deployment", "kubernetes"},
		{"Unknown resource", "custom_resource", "unknown"},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parser.getProviderFromType(tt.resourceType)
			assert.Equal(t, tt.wantProvider, got)
		})
	}
}

func TestParser_DatabaseTypeDetection(t *testing.T) {
	parser := NewParser()
	
	tests := []struct {
		name         string
		resourceType string
		wantType     string
	}{
		{"RDS", "aws_rds_instance", "relational"},
		{"Aurora", "aws_rds_aurora_cluster", "relational"},
		{"DynamoDB", "aws_dynamodb_table", "nosql"},
		{"Cosmos DB", "azurerm_cosmosdb_account", "nosql"},
		{"Redis", "aws_elasticache_redis_cluster", "cache"},
		{"ElastiCache", "aws_elasticache_cluster", "cache"},
		{"Generic", "some_database", "generic"},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parser.getDatabaseType(tt.resourceType)
			assert.Equal(t, tt.wantType, got)
		})
	}
}