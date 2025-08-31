package cloudformation

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
			name:     "CloudFormation YAML file",
			filename: "cloudformation-template.yaml",
			want:     true,
		},
		{
			name:     "CloudFormation YML file",
			filename: "stack.yml",
			want:     true,
		},
		{
			name:     "CloudFormation JSON file",
			filename: "template.json",
			want:     true,
		},
		{
			name:     "CFN prefixed file",
			filename: "cfn-resources.yaml",
			want:     true,
		},
		{
			name:     "CF prefixed file",
			filename: "cf-stack.json",
			want:     true,
		},
		{
			name:     "Generic YAML file",
			filename: "config.yaml",
			want:     true, // We support generic YAML and validate content
		},
		{
			name:     "Terraform file",
			filename: "main.tf",
			want:     false,
		},
		{
			name:     "Go file",
			filename: "main.go",
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
			name: "basic EC2 and S3 resources",
			content: `
AWSTemplateFormatVersion: '2010-09-09'
Description: Basic CloudFormation template

Resources:
  WebServer:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: ami-0c55b159cbfafe1f0
      InstanceType: t2.micro
      Tags:
        - Key: Name
          Value: WebServer
        - Key: Environment
          Value: Production

  DataBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: my-data-bucket
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true
      Tags:
        - Key: Environment
          Value: Production
`,
			wantErr: false,
			check: func(t *testing.T, result interface{}) {
				res := result.(map[string]interface{})
				assert.NotNil(t, res["Resources"])
				assert.NotNil(t, res["Storages"])
			},
		},
		{
			name: "RDS database",
			content: `
Resources:
  Database:
    Type: AWS::RDS::DBInstance
    Properties:
      DBInstanceIdentifier: mydb-instance
      Engine: postgres
      EngineVersion: '13.7'
      DBInstanceClass: db.t3.micro
      AllocatedStorage: 20
      MasterUsername: admin
      MasterUserPassword: !Ref DBPassword
      BackupRetentionPeriod: 7
`,
			wantErr: false,
			check: func(t *testing.T, result interface{}) {
				res := result.(map[string]interface{})
				assert.NotNil(t, res["Databases"])
			},
		},
		{
			name: "VPC and networking",
			content: `
Resources:
  VPC:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: 10.0.0.0/16
      EnableDnsHostnames: true
      EnableDnsSupport: true
      Tags:
        - Key: Name
          Value: MainVPC

  PublicSubnet:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref VPC
      CidrBlock: 10.0.1.0/24
      AvailabilityZone: us-east-1a
      MapPublicIpOnLaunch: true
      Tags:
        - Key: Name
          Value: PublicSubnet

  WebSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Security group for web servers
      VpcId: !Ref VPC
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 80
          ToPort: 80
          CidrIp: 0.0.0.0/0
        - IpProtocol: tcp
          FromPort: 443
          ToPort: 443
          CidrIp: 0.0.0.0/0
      SecurityGroupEgress:
        - IpProtocol: -1
          CidrIp: 0.0.0.0/0
`,
			wantErr: false,
			check: func(t *testing.T, result interface{}) {
				res := result.(map[string]interface{})
				assert.NotNil(t, res["Networks"])
				assert.NotNil(t, res["SecurityGroups"])
			},
		},
		{
			name: "Lambda function",
			content: `
Resources:
  ProcessorFunction:
    Type: AWS::Lambda::Function
    Properties:
      FunctionName: data-processor
      Runtime: python3.9
      Handler: index.handler
      Code:
        S3Bucket: my-code-bucket
        S3Key: function.zip
      Description: Data processing function
      Timeout: 300
      MemorySize: 512
      Environment:
        Variables:
          TABLE_NAME: !Ref DynamoTable
`,
			wantErr: false,
			check: func(t *testing.T, result interface{}) {
				res := result.(map[string]interface{})
				assert.NotNil(t, res["Functions"])
			},
		},
		{
			name: "Load balancer",
			content: `
Resources:
  ApplicationLoadBalancer:
    Type: AWS::ElasticLoadBalancingV2::LoadBalancer
    Properties:
      Name: main-alb
      Type: application
      Scheme: internet-facing
      Subnets:
        - !Ref PublicSubnet1
        - !Ref PublicSubnet2
      SecurityGroups:
        - !Ref ALBSecurityGroup
      Tags:
        - Key: Environment
          Value: Production
`,
			wantErr: false,
			check: func(t *testing.T, result interface{}) {
				res := result.(map[string]interface{})
				assert.NotNil(t, res["LoadBalancers"])
			},
		},
		{
			name: "IAM resources",
			content: `
Resources:
  ServiceUser:
    Type: AWS::IAM::User
    Properties:
      UserName: service-user
      Tags:
        - Key: Purpose
          Value: ServiceAccount

  ApplicationRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: application-role
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: ec2.amazonaws.com
            Action: sts:AssumeRole
      Description: Role for application instances

  S3AccessPolicy:
    Type: AWS::IAM::ManagedPolicy
    Properties:
      PolicyName: S3AccessPolicy
      Description: Policy for S3 access
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Action:
              - s3:GetObject
              - s3:PutObject
            Resource: !Sub 'arn:aws:s3:::${DataBucket}/*'
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
			name: "ECS and containers",
			content: `
Resources:
  ECSCluster:
    Type: AWS::ECS::Cluster
    Properties:
      ClusterName: main-cluster

  TaskDefinition:
    Type: AWS::ECS::TaskDefinition
    Properties:
      Family: app-task
      Cpu: '256'
      Memory: '512'
      NetworkMode: awsvpc
      RequiresCompatibilities:
        - FARGATE
      ContainerDefinitions:
        - Name: app-container
          Image: nginx:latest
          PortMappings:
            - ContainerPort: 80

  ECSService:
    Type: AWS::ECS::Service
    Properties:
      ServiceName: app-service
      Cluster: !Ref ECSCluster
      TaskDefinition: !Ref TaskDefinition
      DesiredCount: 2
      LaunchType: FARGATE
`,
			wantErr: false,
			check: func(t *testing.T, result interface{}) {
				res := result.(map[string]interface{})
				assert.NotNil(t, res["Containers"])
			},
		},
		{
			name: "SQS and SNS",
			content: `
Resources:
  ProcessingQueue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: processing-queue
      MessageRetentionPeriod: 1209600
      VisibilityTimeout: 300

  NotificationTopic:
    Type: AWS::SNS::Topic
    Properties:
      TopicName: notifications
      DisplayName: Application Notifications
      Subscription:
        - Endpoint: admin@example.com
          Protocol: email
`,
			wantErr: false,
			check: func(t *testing.T, result interface{}) {
				res := result.(map[string]interface{})
				assert.NotNil(t, res["Queues"])
				assert.NotNil(t, res["Topics"])
			},
		},
		{
			name: "Parameters and Outputs",
			content: `
AWSTemplateFormatVersion: '2010-09-09'

Parameters:
  InstanceType:
    Type: String
    Default: t2.micro
    Description: EC2 instance type
  
  DBPassword:
    Type: String
    NoEcho: true
    Description: Database password

Outputs:
  WebsiteURL:
    Description: URL of the website
    Value: !GetAtt LoadBalancer.DNSName
  
  DBConnectionString:
    Description: Database connection string
    Value: !Sub 'postgresql://${Database.Endpoint.Address}:5432/mydb'

Resources:
  DummyResource:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: dummy-bucket
`,
			wantErr: false,
			check: func(t *testing.T, result interface{}) {
				res := result.(map[string]interface{})
				metadata := res["Metadata"].(map[string]interface{})
				assert.NotNil(t, metadata)
				assert.NotNil(t, metadata["Parameters"])
				assert.NotNil(t, metadata["Outputs"])
			},
		},
		{
			name: "JSON format CloudFormation",
			content: `{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "S3Bucket": {
      "Type": "AWS::S3::Bucket",
      "Properties": {
        "BucketName": "json-bucket"
      }
    }
  }
}`,
			wantErr: false,
			check: func(t *testing.T, result interface{}) {
				res := result.(map[string]interface{})
				assert.NotNil(t, res["Storages"])
			},
		},
		{
			name:    "invalid CloudFormation",
			content: `This is not a valid CloudFormation template`,
			wantErr: true,
			check:   func(t *testing.T, result interface{}) {},
		},
		{
			name: "non-CloudFormation YAML",
			content: `
# This is a regular YAML file, not CloudFormation
version: 1.0
config:
  setting1: value1
  setting2: value2
`,
			wantErr: true,
			check:   func(t *testing.T, result interface{}) {},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parser.ParseFile("test.yaml", []byte(tt.content))
			
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
				"Containers":     result.Containers,
				"Queues":         result.Queues,
				"Topics":         result.Topics,
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
	
	// Parse a sample CloudFormation template
	content := `
Resources:
  WebServer:
    Type: AWS::EC2::Instance
    Properties:
      InstanceType: t2.micro

  Database:
    Type: AWS::RDS::DBInstance
    Properties:
      Engine: postgres

  DataBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: data-bucket

  LoadBalancer:
    Type: AWS::ElasticLoadBalancingV2::LoadBalancer
    Properties:
      Type: application

  ProcessorFunction:
    Type: AWS::Lambda::Function
    Properties:
      Runtime: python3.9

  MainVPC:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: 10.0.0.0/16
`
	
	result, err := parser.ParseFile("test.yaml", []byte(content))
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
	
	// Check trust boundaries (VPCs)
	assert.NotEmpty(t, model.TrustBoundaries)
	assert.Contains(t, model.TrustBoundaries, "MainVPC")
}

func TestParser_SensitiveParameterDetection(t *testing.T) {
	parser := NewParser()
	
	tests := []struct {
		name      string
		paramName string
		want      bool
	}{
		{"Password parameter", "DBPassword", true},
		{"Secret parameter", "APISecret", true},
		{"Key parameter", "EncryptionKey", true},
		{"Token parameter", "AuthToken", true},
		{"Credential parameter", "ServiceCredential", true},
		{"API key", "ApiKey", true},
		{"Private key", "PrivateKey", true},
		{"Auth parameter", "AuthConfig", true},
		{"Certificate", "SSLCert", true},
		{"SSH key", "SSHKey", true},
		{"Regular parameter", "InstanceType", false},
		{"Regular parameter", "BucketName", false},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parser.isSensitiveParameter(tt.paramName)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParser_CloudFormationValidation(t *testing.T) {
	parser := NewParser()
	
	tests := []struct {
		name    string
		content string
		want    bool
	}{
		{
			name: "Valid CloudFormation with Resources",
			content: `
Resources:
  Bucket:
    Type: AWS::S3::Bucket
`,
			want: true,
		},
		{
			name: "Valid CloudFormation with AWSTemplateFormatVersion",
			content: `
AWSTemplateFormatVersion: '2010-09-09'
`,
			want: true,
		},
		{
			name: "Valid JSON CloudFormation",
			content: `{"Resources": {"Bucket": {"Type": "AWS::S3::Bucket"}}}`,
			want: true,
		},
		{
			name: "Non-CloudFormation YAML",
			content: `
config:
  setting: value
`,
			want: false,
		},
		{
			name:    "Invalid YAML",
			content: `{invalid yaml content`,
			want:    false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parser.isCloudFormationTemplate([]byte(tt.content))
			assert.Equal(t, tt.want, got)
		})
	}
}