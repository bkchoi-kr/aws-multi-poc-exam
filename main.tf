terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.25.0"
    }
  }

  required_version = ">= 1.2.0"
}

provider "aws" {
  region = "ap-northeast-1"
}

locals {
  cluster_name = "poc-eks-tokyo-v1"
  region       = "ap-northeast-1"
  env_name     = "dev"
}

module "vpc" {
  source = "terraform-aws-modules/vpc/aws"

  name = "workload-vpc"
  cidr = "10.100.0.0/16"

  azs             = ["ap-northeast-1a", "ap-northeast-1c"]
  private_subnets = ["10.100.11.0/24", "10.100.12.0/24", "10.100.21.0/24", "10.100.22.0/24"]

  enable_nat_gateway     = false
  one_nat_gateway_per_az = false
  create_igw             = false

  enable_dns_hostnames = true

  private_subnet_tags = {
    "kubernetes.io/cluster/${local.cluster_name}" = "shared"
    "kubernetes.io/role/internal-elb"             = "1"
  }
}

resource "aws_vpc_endpoint" "test" {
  vpc_id              = module.vpc.vpc_id
  service_name        = "com.amazonaws.${local.region}.s3"
  private_dns_enabled = true
  vpc_endpoint_type   = "Interface"
  ip_address_type     = "ipv4"
  subnet_ids          = concat(module.vpc.private_subnets.2, module.vpc.private_subnets.3)
  dns_options {
    dns_record_ip_type                             = "ipv4"
    private_dns_only_for_inbound_resolver_endpoint = false
  }
}


module "vpc_endpoints" {
  source = "terraform-aws-modules/vpc/aws//modules/vpc-endpoints"

  vpc_id = module.vpc.vpc_id

  endpoints = {
    s3 = {
      service             = "s3"
      tags                = { Name = "s3-vpc-endpoint" }
      subnet_ids          = ["subnet-0ba4788fdd9bade19", "subnet-01c49e475e92a7f3f"]
      private_dns_enabled = true
      vpc_endpoint_type   = "Interface"
    }
  }
}



module "endpoints" {
  source  = "terraform-aws-modules/vpc/aws//modules/vpc-endpoints"
  version = "~> 5.1.1"

  vpc_id = module.vpc.vpc_id

  create_security_group = true

  security_group_description = "VPC endpoint security group"
  security_group_rules = {
    ingress_https = {
      description = "HTTPS from VPC"
      cidr_blocks = [module.vpc.vpc_cidr_block]
    }
  }

  endpoints = {
    s3 = {
      service         = "s3"
      service_type    = "Interface"
      #route_table_ids = flatten([module.vpc.private_route_table_ids.2, module.vpc.private_route_table_ids.3])
      #subnet_ids          = concat(module.vpc.private_subnets.2, module.vpc.private_subnets.3)
      subnet_ids          = concat(module.vpc.private_subnets)
      tags = { Name = "${local.env_name}-vpc-s3-ep" }
    },
    sts = {
      service             = "sts"
      private_dns_enabled = true
      subnet_ids          = concat(module.vpc.private_subnets.2, module.vpc.private_subnets.3)
      tags = { Name = "${local.env_name}-vpc-sts-ep" }
    },
    ecr_api = {
      service             = "ecr.api"
      private_dns_enabled = true
      subnet_ids          = concat(module.vpc.private_subnets.2, module.vpc.private_subnets.3)
      tags = { Name = "${local.env_name}-vpc-ecr-api-ep" }
    },
    ecr_dkr = {
      service             = "ecr.dkr"
      private_dns_enabled = true
      subnet_ids          = concat(module.vpc.private_subnets.2, module.vpc.private_subnets.3)
      tags = { Name = "${local.env_name}-vpc-ecr-dkr-ep" }
    }
  }
}


resource "aws_vpc_endpoint" "s3" {
  vpc_id          = module.vpc.vpc_id
  service_name    = "com.amazonaws.${local.region}.s3"
  private_dns_enabled = true
  service_type    = "Interface"
  #route_table_ids = ["${module.vpc.private_route_table_ids.2}, ${module.vpc.private_route_table_ids.3}"]
  #subnet_ids      = ["${module.vpc.private_subnets.2},${module.vpc.private_subnets.3}"]
  subnet_ids      = ["${module.vpc.private_subnets.2}"]

}



module "vpc_endpoints" {
  source = "../../modules/vpc-endpoints"

  vpc_id = module.vpc.vpc_id

  create_security_group      = true
  security_group_name_prefix = "${local.name}-vpc-endpoints-"
  security_group_description = "VPC endpoint security group"
  security_group_rules = {
    ingress_https = {
      description = "HTTPS from VPC"
      cidr_blocks = [module.vpc.vpc_cidr_block]
    }
  }

  endpoints = {
    s3 = {
      service = "s3"
      tags    = { Name = "s3-vpc-endpoint" }
    },
    dynamodb = {
      service         = "dynamodb"
      service_type    = "Gateway"
      route_table_ids = flatten([module.vpc.intra_route_table_ids, module.vpc.private_route_table_ids, module.vpc.public_route_table_ids])
      policy          = data.aws_iam_policy_document.dynamodb_endpoint_policy.json
      tags            = { Name = "dynamodb-vpc-endpoint" }
    },
    ecs = {
      service             = "ecs"
      private_dns_enabled = true
      subnet_ids          = module.vpc.private_subnets
    },
    ecs_telemetry = {
      create              = false
      service             = "ecs-telemetry"
      private_dns_enabled = true
      subnet_ids          = module.vpc.private_subnets
    },
    ecr_api = {
      service             = "ecr.api"
      private_dns_enabled = true
      subnet_ids          = module.vpc.private_subnets
      policy              = data.aws_iam_policy_document.generic_endpoint_policy.json
    },
    ecr_dkr = {
      service             = "ecr.dkr"
      private_dns_enabled = true
      subnet_ids          = module.vpc.private_subnets
      policy              = data.aws_iam_policy_document.generic_endpoint_policy.json
    },
    rds = {
      service             = "rds"
      private_dns_enabled = true
      subnet_ids          = module.vpc.private_subnets
      security_group_ids  = [aws_security_group.rds.id]
    },
  }

  tags = merge(local.tags, {
    Project  = "Secret"
    Endpoint = "true"
  })
}

resource "aws_iam_role" "poc-eks-cluster" {
  name = "poc-eks-cluster-role"

  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "eks.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
POLICY
}

resource "aws_iam_role_policy_attachment" "terraform-eks-cluster-AmazonEKSClusterPolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.terraform-eks-cluster.name
}

resource "aws_iam_role_policy_attachment" "terraform-eks-cluster-AmazonEKSVPCResourceController" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"
  role       = aws_iam_role.terraform-eks-cluster.name
}

resource "aws_security_group" "terraform-eks-cluster" {
  name        = "terraform-eks-cluster"
  description = "Cluster communication with worker nodes"
  vpc_id      = module.vpc.vpc_id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "terraform-eks-cluster"
  }
}

resource "aws_security_group_rule" "terraform-eks-cluster-ingress-workstation-https" {
  cidr_blocks       = ["0.0.0.0/0"]
  description       = "Allow workstation to communicate with the cluster API Server"
  from_port         = 443
  protocol          = "tcp"
  security_group_id = aws_security_group.terraform-eks-cluster.id
  to_port           = 443
  type              = "ingress"
}

resource "aws_eks_cluster" "terraform-eks-cluster" {
  name     = local.cluster_name
  role_arn = aws_iam_role.terraform-eks-cluster.arn
  version  = "1.28"

  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]

  vpc_config {
    security_group_ids = [aws_security_group.terraform-eks-cluster.id]
    #    subnet_ids         = concat(aws_subnet.terraform-eks-public-subnet[*].id, aws_subnet.terraform-eks-private-subnet[*].id)
    subnet_ids = concat(module.vpc.public_subnets, module.vpc.private_subnets)
    #    subnet_ids         = concat(module.vpc.private_subnets)
    endpoint_private_access = true
    endpoint_public_access  = true
  }

  depends_on = [
    aws_iam_role_policy_attachment.terraform-eks-cluster-AmazonEKSClusterPolicy,
    aws_iam_role_policy_attachment.terraform-eks-cluster-AmazonEKSVPCResourceController,
  ]
}

#output "vpc_id" {
#  value = module.vpc.vpc_id
#}
#output "subnet_ids" {
#  value = module.vpc.private_subnets
#}



resource "aws_iam_role" "terraform-eks-node" {
  name = "terraform-eks-node"

  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
POLICY
}

resource "aws_iam_role_policy_attachment" "terraform-eks-node-AmazonEKSWorkerNodePolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.terraform-eks-node.name
}

resource "aws_iam_role_policy_attachment" "terraform-eks-node-AmazonEKS_CNI_Policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.terraform-eks-node.name
}

resource "aws_iam_role_policy_attachment" "terraform-eks-node-AmazonEC2ContainerRegistryReadOnly" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.terraform-eks-node.name
}

resource "aws_eks_node_group" "terraform-eks-m5-large" {
  cluster_name    = aws_eks_cluster.terraform-eks-cluster.name
  node_group_name = "terraform-eks-m5-large"
  node_role_arn   = aws_iam_role.terraform-eks-node.arn
  subnet_ids      = module.vpc.private_subnets
  instance_types  = ["m5.large"]
  disk_size       = 50

  labels = {
    "role" = "terraform-eks-m5-large"
  }

  scaling_config {
    desired_size = 1
    min_size     = 1
    max_size     = 3
  }

  depends_on = [
    aws_iam_role_policy_attachment.terraform-eks-node-AmazonEKSWorkerNodePolicy,
    aws_iam_role_policy_attachment.terraform-eks-node-AmazonEKS_CNI_Policy,
    aws_iam_role_policy_attachment.terraform-eks-node-AmazonEC2ContainerRegistryReadOnly,
  ]

  tags = {
    "Name" = "${aws_eks_cluster.terraform-eks-cluster.name}-terraform-eks-m5-large-Node"
  }
}
