provider "aws" {
  region = "us-gov-east-1" # Change to your preferred region
}
# sudo yum install -y yum-utils
# sudo yum-config-manager --add-repo https://rpm.releases.hashicorp.com/AmazonLinux/hashicorp.repo
# sudo yum -y install terraform
provider "kubernetes" {
  host                   = aws_eks_cluster.master.endpoint
  cluster_ca_certificate = base64decode(aws_eks_cluster.master.certificate_authority[0].data)
  token                  = data.aws_eks_cluster_auth.master.token
}
data "aws_eks_cluster_auth" "master" {
  name = aws_eks_cluster.master.name
}

locals {
  cni_no_proxy = join(",",
    distinct(concat(
      local.no_proxy_input,
      local.vpce_endpoint_list,
      [var.domain, ".${var.domain}"],
      [local.vpc.vpc_cidr]
    ))
  )
  eniConfig      = {}
  no_proxy_input = ["127.0.0.1", "localhost"]
  vpce_endpoint_list = [
    "com.amazonaws.us-gov-east-1.ec2",
    "com.amazonaws.us-gov-east-1.sts",
    "com.amazonaws.us-gov-east-1.ecr.dkr",
    "com.amazonaws.us-gov-east-1.ecr.api",
    "com.amazonaws.us-gov-east-1.logs"
  ]

  vpc = {
    vpc_id   = "vpc-085605eb59b305826"
    vpc_cidr = "10.0.0.0/16"
    pvt_subnet_1 = {
      id           = "subnet-07191f5fc0e398b0e"
      cidr         = "10.0.128.0/20" // private subnet 1
      pvt_rtb_1_id = "rtb-0f1fe911b6b3efc41"

    }
    pvt_subnet_2 = {
      id           = "subnet-0ab332ccfc4c4f934"
      cidr         = "10.0.144.0/20", // private subnet 2
      pvt_rtb_2_id = "rtb-0a82617f4fd8ba39c"
    }
    pvt_subnet_3 = {
      id           = "subnet-0c922d487749a6b77",
      cidr         = "10.0.208.0/20",
      pvt_rtb_3_id = "rtb-0fe448006d1819a73"
    }

  }

}

variable "domain" {
  description = "The domain name to be used"
  default     = "example.com"
}

variable "http_proxy" {
  description = "HTTP proxy configuration"
  default     = "http://proxy.example.com:8080"
}

variable "https_proxy" {
  description = "HTTPS proxy configuration"
  default     = "https://proxy.example.com:8443"
}




resource "aws_security_group" "endpoint_ec2" {
  name   = "endpoint-ec2"
  vpc_id = local.vpc.vpc_id
}

resource "aws_security_group_rule" "endpoint_ec2_443" {
  security_group_id = aws_security_group.endpoint_ec2.id
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks = [
    local.vpc.pvt_subnet_1.cidr,
    local.vpc.pvt_subnet_2.cidr,
    local.vpc.pvt_subnet_3.cidr
  ]
}

resource "aws_vpc_endpoint" "ec2" {
  vpc_id              = local.vpc.vpc_id
  service_name        = "com.amazonaws.us-gov-east-1.ec2"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids = [
    local.vpc.pvt_subnet_1.id,
    local.vpc.pvt_subnet_2.id,
    local.vpc.pvt_subnet_3.id,
  ]

  security_group_ids = [
    aws_security_group.endpoint_ec2.id,
  ]
}

resource "aws_security_group" "endpoint_ecr" {
  name   = "endpoint-ecr"
  vpc_id = local.vpc.vpc_id
}

resource "aws_security_group_rule" "endpoint_ecr_443" {
  security_group_id = aws_security_group.endpoint_ecr.id
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks = [
    local.vpc.pvt_subnet_1.cidr,
    local.vpc.pvt_subnet_2.cidr,
    local.vpc.pvt_subnet_3.cidr
  ]
}

resource "aws_vpc_endpoint" "ecr_api" {
  vpc_id              = local.vpc.vpc_id
  service_name        = "com.amazonaws.us-gov-east-1.ecr.api"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids = [
    local.vpc.pvt_subnet_1.id,
    local.vpc.pvt_subnet_2.id,
    local.vpc.pvt_subnet_3.id
  ]

  security_group_ids = [
    aws_security_group.endpoint_ecr.id,
  ]
}

resource "aws_vpc_endpoint" "ecr_dkr" {
  vpc_id              = local.vpc.vpc_id
  service_name        = "com.amazonaws.us-gov-east-1.ecr.dkr"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids = [
    local.vpc.pvt_subnet_1.id,
    local.vpc.pvt_subnet_2.id,
    local.vpc.pvt_subnet_3.id
  ]

  security_group_ids = [
    aws_security_group.endpoint_ecr.id,
  ]
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = local.vpc.vpc_id
  service_name      = "com.amazonaws.us-gov-east-1.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids = [
    local.vpc.pvt_subnet_1.pvt_rtb_1_id,
    local.vpc.pvt_subnet_2.pvt_rtb_2_id,
    local.vpc.pvt_subnet_3.pvt_rtb_3_id
  ]
}


resource "aws_iam_role" "eks_cluster_role" {
  name = "eks-cluster-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "eks.amazonaws.com"
      }
    }]
  })
}

resource "aws_eks_cluster" "master" {
  name     = "test-vpc"
  role_arn = aws_iam_role.eks_cluster_role.arn

  vpc_config {

    subnet_ids = [
      local.vpc.pvt_subnet_1.id,
      local.vpc.pvt_subnet_2.id,
      local.vpc.pvt_subnet_3.id
    ]

    endpoint_private_access = true
    endpoint_public_access  = true
    public_access_cidrs = [
      "0.0.0.0/0"
    ]
  }

  depends_on = [
  ]
}

resource "aws_eks_node_group" "aza" {
  cluster_name    = aws_eks_cluster.master.name
  node_group_name = "AZa"
  node_role_arn   = aws_iam_role.node_role.arn
  instance_types  = ["t3a.small"]
  subnet_ids = [
    local.vpc.pvt_subnet_1.id
  ]

  scaling_config {
    desired_size = 1
    max_size     = 2
    min_size     = 1
  }

  lifecycle {
    ignore_changes = [
      scaling_config[0].desired_size
    ]
  }

  depends_on = [
    aws_iam_role_policy_attachment.node_policy,
    aws_iam_role_policy_attachment.default-AmazonEKS_CNI_Policy,
    aws_iam_role_policy_attachment.default-AmazonEC2ContainerRegistryReadOnly,
  ]
}

resource "aws_iam_role" "node_role" {
  name = "eks-node-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
  })
}
resource "aws_iam_role_policy_attachment" "node_policy" {
  role       = aws_iam_role.node_role.name
  policy_arn = "arn:aws-us-gov:iam::aws:policy/AmazonEKSWorkerNodePolicy"
}


resource "aws_eks_node_group" "azc" {
  cluster_name    = aws_eks_cluster.master.name
  node_group_name = "AZc"
  node_role_arn   = aws_iam_role.node_role.arn
  instance_types  = ["t3a.small"]
  subnet_ids = [
    local.vpc.pvt_subnet_3.id
  ]

  scaling_config {
    desired_size = 1
    max_size     = 2
    min_size     = 1
  }

  lifecycle {
    ignore_changes = [
      scaling_config[0].desired_size
    ]
  }

  depends_on = [
    aws_iam_role_policy_attachment.node_policy,
    aws_iam_role_policy_attachment.default-AmazonEKS_CNI_Policy,
    aws_iam_role_policy_attachment.default-AmazonEC2ContainerRegistryReadOnly,
  ]
}
resource "aws_iam_role_policy_attachment" "default-AmazonEKS_CNI_Policy" {
  role       = aws_iam_role.node_role.name
  policy_arn = "arn:aws-us-gov:iam::aws:policy/AmazonEKS_CNI_Policy"
}

resource "aws_iam_role_policy_attachment" "default-AmazonEC2ContainerRegistryReadOnly" {
  role       = aws_iam_role.node_role.name
  policy_arn = "arn:aws-us-gov:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

#============================
# VPC CNI Configuration for Pod ENIs
resource "aws_eks_addon" "vpccni" {
  cluster_name                = aws_eks_cluster.master.name
  addon_name                  = "vpc-cni"
  addon_version               = "v1.19.0-eksbuild.1"
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "OVERWRITE"
  service_account_role_arn    = aws_iam_role.vpccni_sa_role.arn
  configuration_values = jsonencode({
    "env" : {
      "AWS_VPC_K8S_CNI_LOG_FILE"           = "stdout"
      "AWS_VPC_K8S_CNI_CUSTOM_NETWORK_CFG" = "true"
      "ENI_CONFIG_LABEL_DEF"               = ""
      "topology.kubernetes.io/zone"        = ""
    }

    "eniConfig" : local.eniConfig
    "tolerations" : [
      {
        "effect"   = "NoExecute"
        "operator" = "Exists"
      },
      {
        "effect"   = "NoSchedule"
        "operator" = "Exists"
    }]
  })
}


##VPC CNI does not support proxy variables per configuration options
resource "kubernetes_env" "vpccni" {
  container = "aws-node"
  metadata {
    name      = "aws-node"
    namespace = "kube-system"
  }
  kind = "DaemonSet"

  api_version = "apps/v1"

  # Setting up environment variables for proxy
  env {
    name  = "HTTP_PROXY"
    value = var.http_proxy
  }

  env {
    name  = "HTTPS_PROXY"
    value = var.https_proxy
  }

  env {
    name  = "NO_PROXY"
    value = local.cni_no_proxy
  }

  depends_on = [
    aws_eks_addon.vpccni,
    aws_security_group.endpoint_ec2,
    aws_eks_cluster.master
  ]
}

resource "aws_iam_role" "vpccni_sa_role" {
  name = "vpccni-sa-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = {
        Service = "eks.amazonaws.com"
      },
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "vpccni_sa_policy" {
  role       = aws_iam_role.vpccni_sa_role.name
  policy_arn = "arn:aws-us-gov:iam::aws:policy/AmazonEKS_CNI_Policy"
}

