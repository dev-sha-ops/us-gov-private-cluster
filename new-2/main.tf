terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "3.72.0"
    }
  }
}
provider "aws" {
  region = var.region
}

//Modify the bucket and dynamoDB table that are used by Terraform
terraform {
  backend "s3" {
    bucket         = "waggsinfra-backend-bucket"
    key            = "private-windows-eks.tfstate"
    region         = "eu-central-1"
  }
}

data terraform_remote_state "network" {
    backend = "s3"
    config = {
        bucket = "waggsinfra-backend-bucket"
        key = "network.tfstate"
        region = "eu-central-1"
     }
}

module "cluster" {
    source = "./eks/cluster"
    region = var.region
    eks_cluster_name = var.eks_cluster_name
    eks_cluster_version = var.eks_cluster_version 
    private_subnet_ids = data.terraform_remote_state.network.outputs.out_private_vpc.private_subnets
    vpc_id = data.terraform_remote_state.network.outputs.out_private_vpc.vpc_id
    bastion_host_SG_id = data.terraform_remote_state.network.outputs.out_bastion_host_security_group_id
    lin_desired_size = var.lin_desired_size
    lin_max_size = var.lin_max_size
    lin_min_size = var.lin_min_size
    lin_instance_type = var.lin_instance_type
    node_host_key_name = var.node_host_key_name
}


