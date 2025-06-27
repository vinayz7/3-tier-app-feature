# main.tf

# Configure the AWS Provider
provider "aws" {
  # The AWS region will be automatically picked up from environment variables (AWS_REGION, AWS_DEFAULT_REGION)
  # or your AWS configuration file (~/.aws/config).
  # region = "us-west-1" # Removed hardcoded region
}

# --- Variables (corresponding to CloudFormation Parameters) ---
variable "environment_name" {
  description = "A name prefix for resources to ensure uniqueness."
  type        = string
  default     = "production storage management"
}

variable "project_tag" {
  description = "A tag value for all resources."
  type        = string
  default     = "Capstone"
}

variable "admin_ip_cidr" {
  description = "Your public IP address CIDR for SSH (to EC2) and kubectl access (to EKS API). IMPORTANT: CHANGE TO YOUR PUBLIC IP CIDR (e.g., 203.0.113.0/32) for kubectl access!"
  type        = string
  default     = "0.0.0.0/0"
}

variable "vpc_cidr" {
  description = "CIDR block for the main VPC."
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidr" {
  description = "CIDR block for the Public Subnet (Frontend ALB and NAT Gateway) in AZ-a."
  type        = string
  default     = "10.0.1.0/24"
}

variable "public_subnet_cidr2" {
  description = "CIDR block for the Public Subnet (Frontend ALB and NAT Gateway) in AZ-c."
  type        = string
  default     = "10.0.5.0/24"
}

variable "private_app_subnet_cidr" {
  description = "CIDR block for the Private Application Subnet (EKS Worker Nodes/App Pods) in AZ-a."
  type        = string
  default     = "10.0.2.0/24"
}

variable "private_app_subnet_cidr2" {
  description = "CIDR block for the Private Application Subnet (EKS Worker Nodes/App Pods) in AZ-c."
  type        = string
  default     = "10.0.6.0/24"
}

variable "private_db_subnet_cidr" {
  description = "CIDR block for the Private Database Subnet (RDS MySQL) in AZ-a."
  type        = string
  default     = "10.0.3.0/24"
}

variable "private_db_subnet_cidr2" {
  description = "CIDR block for the Private Database Subnet (RDS MySQL) in AZ-c."
  type        = string
  default     = "10.0.4.0/24"
}

variable "availability_zone" {
  description = "The Availability Zone to deploy primary resources into (AZ-a)."
  type        = string
  default     = "us-east-2a" # Changed to us-east-2a as per error message
}

variable "availability_zone2" {
  description = "The second Availability Zone for RDS and EKS (AZ-c)."
  type        = string
  default     = "us-east-2c" # Changed to us-east-2c as per error message
}

variable "eks_cluster_name" {
  description = "Name of the EKS cluster."
  type        = string
  default     = "eks-cluster"
}

variable "eks_node_instance_type" {
  description = "EC2 instance type for EKS worker nodes."
  type        = string
  default     = "t3.medium"
}

variable "eks_node_min_size" {
  description = "Minimum number of EKS worker nodes."
  type        = number
  default     = 1
}

variable "eks_node_desired_size" {
  description = "Desired number of EKS worker nodes."
  type        = number
  default     = 2
}

variable "eks_node_max_size" {
  description = "Maximum number of EKS worker nodes."
  type        = number
  default     = 3
}

variable "db_instance_identifier" {
  description = "Identifier for the RDS DB instance."
  type        = string
  default     = "database-1"
}

variable "db_name" {
  description = "Initial database name."
  type        = string
  default     = "database-1"
}

variable "db_instance_class" {
  description = "The DB instance class (e.g., db.t3.micro)."
  type        = string
  default     = "db.t3.micro"
}

variable "db_allocated_storage" {
  description = "The amount of storage (GB) to allocate to the DB instance."
  type        = number
  default     = 20
}

variable "ssh_key_pair_name" {
  description = "The EC2 Key Pair Name for SSH access to EKS worker nodes."
  type        = string
  default     = "mykey" # IMPORTANT: Replace with an existing EC2 Key Pair Name in your AWS account
}


# --- 1. VPC and Networking Components (Foundation) ---
resource "aws_vpc" "my_vpc" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name    = "${var.environment_name}-VPC"
    Project = var.project_tag
  }
}

resource "aws_internet_gateway" "internet_gateway" {
  vpc_id = aws_vpc.my_vpc.id

  tags = {
    Name    = "${var.environment_name}-IGW"
    Project = var.project_tag
  }
}

# No explicit aws_vpc_gateway_attachment needed, as aws_internet_gateway handles attachment via vpc_id

resource "aws_subnet" "public_subnet" {
  vpc_id                  = aws_vpc.my_vpc.id
  cidr_block              = var.public_subnet_cidr
  map_public_ip_on_launch = true
  availability_zone       = var.availability_zone

  tags = {
    Name                                    = "${var.environment_name}-PublicSubnet-a"
    Project                                 = var.project_tag
    "kubernetes.io/role/elb"                = "1"
    "kubernetes.io/cluster/${var.eks_cluster_name}" = "owned"
  }
}

resource "aws_subnet" "public_subnet2" {
  vpc_id                  = aws_vpc.my_vpc.id
  cidr_block              = var.public_subnet_cidr2
  map_public_ip_on_launch = true
  availability_zone       = var.availability_zone2

  tags = {
    Name                                    = "${var.environment_name}-PublicSubnet-c"
    Project                                 = var.project_tag
    "kubernetes.io/role/elb"                = "1"
    "kubernetes.io/cluster/${var.eks_cluster_name}" = "owned"
  }
}

resource "aws_subnet" "private_app_subnet" {
  vpc_id            = aws_vpc.my_vpc.id
  cidr_block        = var.private_app_subnet_cidr
  availability_zone = var.availability_zone

  tags = {
    Name                                    = "${var.environment_name}-PrivateAppSubnet-a"
    Project                                 = var.project_tag
    "kubernetes.io/role/internal-elb"       = "1"
    "kubernetes.io/cluster/${var.eks_cluster_name}" = "owned"
  }
}

resource "aws_subnet" "private_app_subnet2" {
  vpc_id            = aws_vpc.my_vpc.id
  cidr_block        = var.private_app_subnet_cidr2
  availability_zone = var.availability_zone2

  tags = {
    Name                                    = "${var.environment_name}-PrivateAppSubnet-c"
    Project                                 = var.project_tag
    "kubernetes.io/role/internal-elb"       = "1"
    "kubernetes.io/cluster/${var.eks_cluster_name}" = "owned"
  }
}

resource "aws_subnet" "private_db_subnet" {
  vpc_id            = aws_vpc.my_vpc.id
  cidr_block        = var.private_db_subnet_cidr
  availability_zone = var.availability_zone

  tags = {
    Name    = "${var.environment_name}-PrivateDbSubnet-a"
    Project = var.project_tag
  }
}

resource "aws_subnet" "private_db_subnet2" {
  vpc_id            = aws_vpc.my_vpc.id
  cidr_block        = var.private_db_subnet_cidr2
  availability_zone = var.availability_zone2

  tags = {
    Name    = "${var.environment_name}-PrivateDbSubnet-c"
    Project = var.project_tag
  }
}

resource "aws_eip" "nat_gateway_eip" {
  # Removed 'vpc = true' as it's not a valid argument for new EIP allocations in a VPC context.
  # The EIP will automatically be in a VPC when associated with a NAT Gateway.
  tags = {
    Name    = "${var.environment_name}-NatGatewayEIP-a"
    Project = var.project_tag
  }
}

resource "aws_nat_gateway" "nat_gateway" {
  allocation_id = aws_eip.nat_gateway_eip.id
  subnet_id     = aws_subnet.public_subnet.id

  tags = {
    Name    = "${var.environment_name}-NatGateway-a"
    Project = var.project_tag
  }
  # depends_on: aws_internet_gateway.internet_gateway (Terraform infers this implicitly)
}

resource "aws_eip" "nat_gateway_eip2" {
  # Removed 'vpc = true' as it's not a valid argument for new EIP allocations in a VPC context.
  # The EIP will automatically be in a VPC when associated with a NAT Gateway.
  tags = {
    Name    = "${var.environment_name}-NatGatewayEIP-c"
    Project = var.project_tag
  }
}

resource "aws_nat_gateway" "nat_gateway2" {
  allocation_id = aws_eip.nat_gateway_eip2.id
  subnet_id     = aws_subnet.public_subnet2.id

  tags = {
    Name    = "${var.environment_name}-NatGateway-c"
    Project = var.project_tag
  }
  # depends_on: aws_internet_gateway.internet_gateway (Terraform infers this implicitly)
}

resource "aws_route_table" "public_route_table" {
  vpc_id = aws_vpc.my_vpc.id

  tags = {
    Name    = "${var.environment_name}-PublicRT"
    Project = var.project_tag
  }
}

resource "aws_route" "public_route" {
  route_table_id         = aws_route_table.public_route_table.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.internet_gateway.id
}

resource "aws_route_table_association" "public_subnet_association" {
  subnet_id      = aws_subnet.public_subnet.id
  route_table_id = aws_route_table.public_route_table.id
}

resource "aws_route_table_association" "public_subnet_association2" {
  subnet_id      = aws_subnet.public_subnet2.id
  route_table_id = aws_route_table.public_route_table.id
}

resource "aws_route_table" "private_app_route_table" {
  vpc_id = aws_vpc.my_vpc.id

  tags = {
    Name    = "${var.environment_name}-PrivateAppRT"
    Project = var.project_tag
  }
}

resource "aws_route" "private_app_route" {
  route_table_id         = aws_route_table.private_app_route_table.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.nat_gateway.id
  # depends_on: aws_nat_gateway.nat_gateway (Terraform infers this implicitly)
}

resource "aws_route_table_association" "private_app_subnet_association" {
  subnet_id      = aws_subnet.private_app_subnet.id
  route_table_id = aws_route_table.private_app_route_table.id
}

resource "aws_route_table" "private_app_route_table2" {
  vpc_id = aws_vpc.my_vpc.id

  tags = {
    Name    = "${var.environment_name}-PrivateAppRT-c"
    Project = var.project_tag
  }
}

resource "aws_route" "private_app_route2" {
  route_table_id         = aws_route_table.private_app_route_table2.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.nat_gateway2.id
  # depends_on: aws_nat_gateway.nat_gateway2 (Terraform infers this implicitly)
}

resource "aws_route_table_association" "private_app_subnet_association2" {
  subnet_id      = aws_subnet.private_app_subnet2.id
  route_table_id = aws_route_table.private_app_route_table2.id
}

resource "aws_route_table" "private_db_route_table" {
  vpc_id = aws_vpc.my_vpc.id

  tags = {
    Name    = "${var.environment_name}-PrivateDbRT"
    Project = var.project_tag
  }
}

resource "aws_route_table_association" "private_db_subnet_association" {
  subnet_id      = aws_subnet.private_db_subnet.id
  route_table_id = aws_route_table.private_db_route_table.id
}

resource "aws_route_table_association" "private_db_subnet_association2" {
  subnet_id      = aws_subnet.private_db_subnet2.id
  route_table_id = aws_route_table.private_db_route_table.id
}


# --- 2. Define all base Security Groups ---
resource "aws_security_group" "load_balancer_sg" {
  name_prefix = "${var.environment_name}-LoadBalancerSG-"
  description = "Security group for Load Balancer"
  vpc_id      = aws_vpc.my_vpc.id

  tags = {
    Name    = "${var.environment_name}-LoadBalancerSG"
    Project = var.project_tag
  }
}

resource "aws_security_group" "eks_worker_node_sg" {
  name_prefix = "${var.environment_name}-EKSWorkerNodeSG-"
  description = "Security group for EKS worker nodes"
  vpc_id      = aws_vpc.my_vpc.id

  tags = {
    Name    = "${var.environment_name}-EKSWorkerNodeSG"
    Project = var.project_tag
  }
}

resource "aws_security_group" "eks_cluster_sg" {
  name_prefix = "${var.environment_name}-EKSClusterSG-"
  description = "Security group for EKS cluster control plane access"
  vpc_id      = aws_vpc.my_vpc.id

  tags = {
    Name    = "${var.environment_name}-EKSClusterSG"
    Project = var.project_tag
  }
}

resource "aws_security_group" "rds_sg" {
  name_prefix = "${var.environment_name}-RDSSG-"
  description = "Security group for RDS"
  vpc_id      = aws_vpc.my_vpc.id

  tags = {
    Name    = "${var.environment_name}-RDSSG"
    Project = var.project_tag
  }
}


# --- 3. IAM Roles for EKS ---
resource "aws_iam_role" "eks_cluster_role" {
  name = "${var.environment_name}-EKSClusterRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "eks.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      },
    ]
  })

  tags = {
    Name    = "${var.environment_name}-EKSClusterRole"
    Project = var.project_tag
  }
}

resource "aws_iam_role_policy_attachment" "eks_cluster_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.eks_cluster_role.name
}

resource "aws_iam_role_policy_attachment" "eks_vpc_resource_controller_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"
  role       = aws_iam_role.eks_cluster_role.name
}

resource "aws_iam_role" "eks_node_instance_role" {
  name = "${var.environment_name}-EKSNodeInstanceRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      },
    ]
  })

  tags = {
    Name    = "${var.environment_name}-EKSNodeInstanceRole"
    Project = var.project_tag
  }
}

resource "aws_iam_role_policy_attachment" "eks_worker_node_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.eks_node_instance_role.name
}

resource "aws_iam_role_policy_attachment" "ecr_read_only_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.eks_node_instance_role.name
}

resource "aws_iam_role_policy_attachment" "eks_cni_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.eks_node_instance_role.name
}


# --- 4. EKS Cluster ---
resource "aws_eks_cluster" "eks_cluster" {
  name     = var.eks_cluster_name
  version  = "1.29"
  role_arn = aws_iam_role.eks_cluster_role.arn

  vpc_config {
    security_group_ids = [aws_security_group.eks_cluster_sg.id]
    subnet_ids = [
      aws_subnet.public_subnet.id,
      aws_subnet.public_subnet2.id,
      aws_subnet.private_app_subnet.id,
      aws_subnet.private_app_subnet2.id,
    ]
    endpoint_private_access = false # Set to true for private access only
    endpoint_public_access  = true
  }

  access_config {
    authentication_mode            = "API_AND_CONFIG_MAP"
    bootstrap_cluster_creator_admin_permissions = true
  }

  tags = {
    Name    = "${var.environment_name}-EksCluster"
    Project = var.project_tag
  }
}

# --- 5. RDS DB Subnet Group ---
resource "aws_db_subnet_group" "my_rds_db_subnet_group" {
  # The 'name' attribute must be lowercase, alphanumeric, and can contain hyphens.
  # Converting environment_name to lowercase to adhere to the naming convention.
  name        = "${lower(var.environment_name)}-rds-db-subnet-group"
  description = "Subnet group for RDS instance"
  subnet_ids = [
    aws_subnet.private_db_subnet.id,
    aws_subnet.private_db_subnet2.id,
  ]

  tags = {
    Name    = "${var.environment_name}-RDSDBSubnetGroup"
    Project = var.project_tag
  }
}

# --- 6. RDS MySQL Instance ---
resource "aws_db_instance" "my_rds_db_instance" {
  identifier           = var.db_instance_identifier
  engine               = "mysql"
  engine_version       = "8.0.32"
  username             = "admin"       # Hardcoded username
  password             = "admin123" # Hardcoded password - REMOVE THIS FOR PRODUCTION!
  instance_class       = var.db_instance_class
  allocated_storage    = var.db_allocated_storage
  db_subnet_group_name = aws_db_subnet_group.my_rds_db_subnet_group.name
  vpc_security_group_ids = [aws_security_group.rds_sg.id]
  publicly_accessible  = true          # Changed from false to true
  backup_retention_period = 7
  multi_az             = false
  db_name              = var.db_name
  skip_final_snapshot  = true # Set to false for production to retain final snapshot

  tags = {
    Name    = "${var.environment_name}-DB"
    Project = var.project_tag
  }
}

# --- 7. Security Group INGRESS / EGRESS Rules ---
resource "aws_security_group_rule" "load_balancer_sg_ingress_http" {
  type              = "ingress"
  from_port         = 80
  to_port           = 80
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.load_balancer_sg.id
}

resource "aws_security_group_rule" "eks_worker_node_sg_ingress_from_load_balancer" {
  type                     = "ingress"
  from_port                = 8080
  to_port                  = 8080
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.load_balancer_sg.id
  security_group_id        = aws_security_group.eks_worker_node_sg.id
}

resource "aws_security_group_rule" "eks_worker_node_sg_ingress_self" {
  type                     = "ingress"
  from_port                = 0
  to_port                  = 65535
  protocol                 = "-1" # All protocols
  source_security_group_id = aws_security_group.eks_worker_node_sg.id
  security_group_id        = aws_security_group.eks_worker_node_sg.id
}

resource "aws_security_group_rule" "eks_worker_node_sg_ingress_ssh" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = [var.admin_ip_cidr]
  security_group_id = aws_security_group.eks_worker_node_sg.id
}

resource "aws_security_group_rule" "eks_cluster_sg_ingress_admin" {
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = [var.admin_ip_cidr]
  security_group_id = aws_security_group.eks_cluster_sg.id
}

resource "aws_security_group_rule" "eks_cluster_sg_ingress_from_worker_nodes" {
  type                     = "ingress"
  from_port                = 10250 # Kubelet port range typically
  to_port                  = 65535 # Ephemeral ports
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.eks_worker_node_sg.id
  security_group_id        = aws_security_group.eks_cluster_sg.id
}

resource "aws_security_group_rule" "rds_sg_ingress_from_eks_worker_nodes" {
  type                     = "ingress"
  from_port                = 3306
  to_port                  = 3306
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.eks_worker_node_sg.id
  security_group_id        = aws_security_group.rds_sg.id
}

# --- 8. EKS Managed Node Group ---
resource "aws_eks_node_group" "eks_node_group" {
  cluster_name    = aws_eks_cluster.eks_cluster.name
  node_group_name = "${var.environment_name}-EKSNodeGroup"
  node_role_arn   = aws_iam_role.eks_node_instance_role.arn
  subnet_ids = [
    aws_subnet.private_app_subnet.id,
    aws_subnet.private_app_subnet2.id,
  ]
  instance_types = [var.eks_node_instance_type]

  scaling_config {
    min_size     = var.eks_node_min_size
    desired_size = var.eks_node_desired_size
    max_size     = var.eks_node_max_size
  }

  ami_type = "AL2_x86_64" # Amazon Linux 2 AMI

  remote_access {
    ec2_ssh_key               = var.ssh_key_pair_name
    source_security_group_ids = [aws_security_group.eks_worker_node_sg.id]
  }

  labels = {
    Environment   = var.environment_name
    NodeGroupType = "app-nodes"
  }

  tags = {
    Name    = "${var.environment_name}-EKSNodeGroup"
    Project = var.project_tag
  }

  # Ensure the node group creation waits for the EKS cluster to be active
  depends_on = [
    aws_iam_role_policy_attachment.eks_cluster_policy,
    aws_iam_role_policy_attachment.eks_vpc_resource_controller_policy,
    aws_iam_role_policy_attachment.eks_worker_node_policy,
    aws_iam_role_policy_attachment.ecr_read_only_policy,
    aws_iam_role_policy_attachment.eks_cni_policy,
  ]
}


# --- Outputs ---
output "vpc_id" {
  description = "The ID of the VPC"
  value       = aws_vpc.my_vpc.id
}

output "public_subnet_id_az_a" {
  description = "The ID of the Public Subnet in us-east-2a"
  value       = aws_subnet.public_subnet.id
}

output "public_subnet_id_az_c" {
  description = "The ID of the Public Subnet in us-east-2c"
  value       = aws_subnet.public_subnet2.id
}

output "private_app_subnet_id_az_a" {
  description = "The ID of the Private Application Subnet in us-east-2a"
  value       = aws_subnet.private_app_subnet.id
}

output "private_app_subnet_id_az_c" {
  description = "The ID of the Private Application Subnet in us-east-2c"
  value       = aws_subnet.private_app_subnet2.id
}

output "private_db_subnet_id_az_a" {
  description = "The ID of the Private Database Subnet in us-east-2a"
  value       = aws_subnet.private_db_subnet.id
}

output "private_db_subnet_id_az_c" {
  description = "The ID of the Private Database Subnet in us-east-2c"
  value       = aws_subnet.private_db_subnet2.id
}

output "eks_worker_node_security_group_id" {
  description = "Security Group ID for EKS Worker Nodes"
  value       = aws_security_group.eks_worker_node_sg.id
}

output "rds_security_group_id" {
  description = "Security Group ID for RDS"
  value       = aws_security_group.rds_sg.id
}

output "db_endpoint_address" {
  description = "The address of the RDS DB instance"
  value       = aws_db_instance.my_rds_db_instance.address
}

output "db_endpoint_port" {
  description = "The port of the RDS DB instance"
  value       = aws_db_instance.my_rds_db_instance.port
}

output "eks_cluster_name_output" {
  description = "The name of the EKS cluster"
  value       = aws_eks_cluster.eks_cluster.name
}

output "eks_cluster_endpoint" {
  description = "The endpoint for the EKS cluster API"
  value       = aws_eks_cluster.eks_cluster.endpoint
}
