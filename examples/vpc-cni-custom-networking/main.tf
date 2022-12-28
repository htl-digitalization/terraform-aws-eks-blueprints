provider "aws" {
  region = local.region
}

provider "kubernetes" {
  host                   = module.eks_blueprints.eks_cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks_blueprints.eks_cluster_certificate_authority_data)
  token                  = data.aws_eks_cluster_auth.this.token
}

provider "helm" {
  kubernetes {
    host                   = module.eks_blueprints.eks_cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks_blueprints.eks_cluster_certificate_authority_data)
    token                  = data.aws_eks_cluster_auth.this.token
  }
}

provider "kubectl" {
  apply_retry_count      = 10
  host                   = module.eks_blueprints.eks_cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks_blueprints.eks_cluster_certificate_authority_data)
  load_config_file       = false
  token                  = data.aws_eks_cluster_auth.this.token
}

data "aws_eks_cluster_auth" "this" {
  name = module.eks_blueprints.eks_cluster_id
}

data "aws_caller_identity" "current" {}
data "aws_availability_zones" "available" {}

locals {
  name   = basename(path.cwd)
  region = "ap-southeast-1"

  cluster_version = "1.24"

  azs                = slice(data.aws_availability_zones.available.names, 0, 3)
  vpc_cidr           = "155.0.0.0/16"
  # secondary_vpc_cidr = "100.99.0.0/16"

  tags = {
    Blueprint  = local.name
    GithubRepo = "github.com/aws-ia/terraform-aws-eks-blueprints"
  }
}

#---------------------------------------------------------------
# EKS Blueprints
#---------------------------------------------------------------

module "eks_blueprints" {
  source = "../.."

  cluster_name    = local.name
  cluster_version = local.cluster_version

  vpc_id                   = module.vpc.vpc_id
  # private_subnet_ids       = slice(module.vpc.private_subnets, 0, 3)
  public_subnet_ids       = slice(module.vpc.public_subnets, 0, 3)
  control_plane_subnet_ids = module.vpc.public_subnets

  # https://github.com/aws-ia/terraform-aws-eks-blueprints/issues/485
  # https://github.com/aws-ia/terraform-aws-eks-blueprints/issues/494
  cluster_kms_key_additional_admin_arns = [data.aws_caller_identity.current.arn]

  managed_node_groups = {
    mng_ng_1 = {
      # Node Group configuration
      node_group_name = "mng_ng_1" # Max 40 characters for node group name

      # custom_ami_id is optional when you provide ami_type. Enter the Custom AMI id if you want to use your own custom AMI
      # custom_ami_id  = data.aws_ami.amazonlinux2eks.id
      custom_ami_id  = data.aws_ssm_parameter.eks_optimized_ami.value
      capacity_type  = "ON_DEMAND"  # ON_DEMAND or SPOT
      instance_types = ["t3.large"] # List of instances to get capacity from multipe pools

      # Launch template configuration
      create_launch_template = true              # false will use the default launch template
      launch_template_os     = "amazonlinux2eks" # amazonlinux2eks or bottlerocket

      # pre_userdata will be applied by using custom_ami_id or ami_type
      pre_userdata = <<-EOT
            yum install -y amazon-ssm-agent
            systemctl enable amazon-ssm-agent && systemctl start amazon-ssm-agent
        EOT

      # post_userdata will be applied only by using custom_ami_id
      post_userdata = <<-EOT
            echo "Bootstrap successfully completed! You can further apply config or install to run after bootstrap if needed"
      EOT

      # kubelet_extra_args used only when you pass custom_ami_id;
      # --node-labels is used to apply Kubernetes Labels to Nodes
      # --register-with-taints used to apply taints to Nodes
      # e.g., 
      kubelet_extra_args=  "--node-labels=WorkerType=ON_DEMAND,noderole=spark --max-pods=58"
      # kubelet_extra_args = "--node-labels=WorkerType=ON_DEMAND,noderole=spark --register-with-taints=test=true:NoSchedule --max-pods=20"

      # bootstrap_extra_args used only when you pass custom_ami_id. Allows you to change the Container Runtime for Nodes
      # e.g., bootstrap_extra_args="--use-max-pods false --container-runtime containerd"
      bootstrap_extra_args = "--use-max-pods false --container-runtime containerd"

      # Taints can be applied through EKS API or through Bootstrap script using kubelet_extra_args
      k8s_taints = []

      # Node Labels can be applied through EKS API or through Bootstrap script using kubelet_extra_args
      k8s_labels = {
        Environment = "preprod"
        Zone        = "dev"
        Runtime     = "containerd"
      }

      # enable_monitoring = true
      eni_delete        = true
      public_ip         = true # Use this to enable public IP for EC2 instances; only for public subnets used in launch templates

      # Node Group scaling configuration
      desired_size    = 1
      max_size        = 1
      min_size        = 1
      max_unavailable = 1 # or percentage = 20

      block_device_mappings = [
        {
          device_name = "/dev/xvda"
          volume_type = "gp3"
          volume_size = 20
        }
      ]

      # Node Group network configuration
      subnet_type = "public" # public or private - Default uses the private subnets used in control plane if you don't pass the "subnet_ids"
      subnet_ids = module.vpc.public_subnets # Defaults to private subnet-ids used by EKS Control plane. Define your private/public subnets list with comma separated subnet_ids  = ['subnet1','subnet2','subnet3']

      additional_iam_policies = [] # Attach additional IAM policies to the IAM role attached to this worker group

      # SSH ACCESS Optional - Recommended to use SSM Session manager
      remote_access         = false
      ec2_ssh_key           = ""
      ssh_security_group_id = ""

      additional_tags = {
        ExtraTag    = "mng-custom-ami"
        Name        = "mng-custom-ami"
        subnet_type = "public"
      }
      launch_template_tags = {
        SomeAwsProviderDefaultTag1: "TRUE"
        SomeAwsProviderDefaultTag2: "TRUE"
      }
    }
  }

  # self_managed_node_groups = {
  #     self_mg_5 = {
  #       node_group_name      = "self-managed-ondemand"
  #       instance_type        = "t3.large"
  #       custom_ami_id        = "ami-0dfaa019a300f219c" # Bring your own custom AMI generated by Packer/ImageBuilder/Puppet etc.
  #       capacity_type        = ""                      # Optional Use this only for SPOT capacity as capacity_type = "spot"
  #       launch_template_os   = "amazonlinux2eks"       # amazonlinux2eks  or bottlerocket or windows
  #       pre_userdata         = <<-EOT
  #           yum install -y amazon-ssm-agent
  #           systemctl enable amazon-ssm-agent && systemctl start amazon-ssm-agent
  #       EOT
  #       post_userdata        = ""

  #       create_iam_role = false # Changing `crm5eate_iam_role=false` to bring your own IAM Role
  #       iam_role_arn              = "<ENTER_IAM_ROLE_ARN>" # custom IAM role for aws-auth mapping; used when create_iam_role = false
  #       iam_instance_profile_name = "<ENTER_IAM_INSTANCE_PROFILE_NAME>" # IAM instance profile name for Launch templates; used when create_iam_role = false

  #       kubelet_extra_args   = "--node-labels=WorkerType=ON_DEMAND,noderole=spark --register-with-taints=test=true:NoSchedule --max-pods=20"
  #       bootstrap_extra_args = ""
  #       block_device_mapping = [
  #         {
  #           device_name = "/dev/xvda" # mount point to /
  #           volume_type = "gp3"
  #           volume_size = 20
  #         },
  #         {
  #           device_name = "/dev/xvdf" # mount point to /local1 (it could be local2, depending upon the disks are attached during boot)
  #           volume_type = "gp3"
  #           volume_size = 50
  #           iops        = 3000
  #           throughput  = 125
  #         },m5
  #         {
  #           device_name = "/dev/xvdg" # mount point to /local2 (it could be local1, depending upon the disks are attached during boot)
  #           volume_type = "gp3"
  #           volume_size = 100
  #           iops        = 3000
  #           throughput  = 125
  #         }
  #       ]
  #       enable_monitoring = false
  #       public_ip         = true # Enable only for public subnets

  #       # AUTOSCALING
  #       desired_size = 1
  #       max_size   = 1
  #       min_size   = 1
  #       subnet_ids = [] # Mandatory Public or Private Subnet IDs
  #       additional_tags = {
  #         ExtraTag    = "t3large-on-demand"
  #         Name        = "t3large-on-demand"
  #         subnet_type = "public"
  #       }
  #       launch_template_tags = {
  #         SomeAwsProviderDefaultTag1: "TRUE"
  #         SomeAwsProviderDefaultTag2: "TRUE"
  #       }
  #       additional_iam_policies = []
  #     },
  #   }
  tags = local.tags
}

module "eks_blueprints_kubernetes_addons" {
  source = "../../modules/kubernetes-addons"

  eks_cluster_id       = module.eks_blueprints.eks_cluster_id
  eks_cluster_endpoint = module.eks_blueprints.eks_cluster_endpoint
  eks_oidc_provider    = module.eks_blueprints.oidc_provider
  eks_cluster_version  = module.eks_blueprints.eks_cluster_version
  enable_argocd = false
  enable_calico = false
  enable_amazon_eks_vpc_cni            = false
  enable_amazon_eks_coredns            = false
  enable_amazon_eks_kube_proxy         = false
  enable_aws_efs_csi_driver = false

  # enable_ingress_nginx = true
  # enable_external_dns = true
  # eks_cluster_domain = "eks-cluster.tp-packing.com"

  # enable_cert_manager = true
  # enable_velero           = true
  velero_backup_s3_bucket = module.velero_backup_s3_bucket.s3_bucket_id

  enable_amazon_eks_aws_ebs_csi_driver = false
  self_managed_aws_ebs_csi_driver_helm_config = {
    set_values = [
      {
        name  = "node.tolerateAllTaints"
        value = "true"
    }]
  }
  # velero_backup_s3_bucket = "tpp-eks-backup"

  # enable_aws_load_balancer_controller = true

  # external_dns_route53_zone_arns = [
  #   "arn:aws:route53::735929869940:hostedzone/Z03340993JGGJ7QTM0399"
  # ]

  # argocd_manage_add_ons               = true

  # argocd_helm_config = {
  #   name             = "argo-cd"
  #   chart            = "argo-cd"
  #   repository       = "https://argoproj.github.io/argo-helm"
  #   version          = "3.29.5"
  #   namespace        = "argocd"
  #   timeout          = "1200"
  #   create_namespace = true
  #   # values = [templatefile("${path.module}/argocd-values.yaml", {})]
  # }

  # argocd_applications = {
  #   # workloads = {
  #   #   path                = "envs/dev"
  #   #   repo_url            = "https://github.com/aws-samples/eks-blueprints-workloads.git"
  #   #   values              = {}
  #   #   type                = "helm"            # Optional, defaults to helm.
  #   # }
  #   # kustomize_apps = {
  #   #   /*
  #   #     This points to a single application with no overlays, but it could easily
  #   #     point to a a specific overlay for an environment like "dev", and/or utilize
  #   #     the ArgoCD app of apps model to install many additional ArgoCD apps.
  #   #   */
  #   #   path                = "argocd-example-apps/kustomize-guestbook/"
  #   #   repo_url            = "https://github.com/argoproj/argocd-example-apps.git"
  #   #   type                = "kustomize"
  #   # }
  #   addons = {
  #     path                = "chart"
  #      repo_url            = "git@github.com:aws-samples/eks-blueprints-add-ons.git"
  #     add_on_application  = true              # Indicates the root add-on application.
  #                                             # If provided, the type must be set to "helm" for the root add-on application.
  #     ssh_key_secret_name = "github-ssh-key"  # Needed for private repos
  #     values              = {}
  #     type                = "helm"            # Optional, defaults to helm.
  #     #ignoreDifferences   = [ # Enable this to ignore children apps' sync policy
  #     #  {
  #     #    group        = "argoproj.io"
  #     #    kind         = "Application"
  #     #    jsonPointers = ["/spec/syncPolicy"]
  #     #  }
  #     #]
  #   }
  # }
  amazon_eks_vpc_cni_config = {
    # Version 1.6.3-eksbuild.2 or later of the Amazon VPC CNI is required for custom networking
    # Version 1.9.0 or later (for version 1.20 or earlier clusters or 1.21 or later clusters configured for IPv4)
    # or 1.10.1 or later (for version 1.21 or later clusters configured for IPv6) of the Amazon VPC CNI for prefix delegation
    addon_version     = data.aws_eks_addon_version.latest["vpc-cni"].version
    resolve_conflicts = "OVERWRITE"
  }

  tags = local.tags

  depends_on = [
    # Modify VPC CNI ahead of addons
    null_resource.kubectl_set_env
  ]
}

data "aws_eks_addon_version" "latest" {
  for_each = toset(["vpc-cni"])

  addon_name         = each.value
  kubernetes_version = module.eks_blueprints.eks_cluster_version
  most_recent        = true
}

#---------------------------------------------------------------
# Modify VPC CNI deployment
#---------------------------------------------------------------

locals {
  kubeconfig = yamlencode({
    apiVersion      = "v1"
    kind            = "Config"
    current-context = "terraform"
    clusters = [{
      name = module.eks_blueprints.eks_cluster_id
      cluster = {
        certificate-authority-data = module.eks_blueprints.eks_cluster_certificate_authority_data
        server                     = module.eks_blueprints.eks_cluster_endpoint
      }
    }]
    contexts = [{
      name = "terraform"
      context = {
        cluster = module.eks_blueprints.eks_cluster_id
        user    = "terraform"
      }
    }]
    users = [{
      name = "terraform"
      user = {
        token = data.aws_eks_cluster_auth.this.token
      }
    }]
  })
}

resource "null_resource" "kubectl_set_env" {
  triggers = {}

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    environment = {
      KUBECONFIG = base64encode(local.kubeconfig)
    }

    # Reference https://aws.github.io/aws-eks-best-practices/reliability/docs/networkmanagement/#cni-custom-networking
    # Reference https://docs.aws.amazon.com/eks/latest/userguide/cni-increase-ip-addresses.html
    command = <<-EOT
      # Custom networking
      kubectl set env daemonset aws-node -n kube-system AWS_VPC_K8S_CNI_CUSTOM_NETWORK_CFG=true --kubeconfig <(echo $KUBECONFIG | base64 -d)
      kubectl set env daemonset aws-node -n kube-system ENI_CONFIG_LABEL_DEF=failure-domain.beta.kubernetes.io/zone --kubeconfig <(echo $KUBECONFIG | base64 -d)


      # Prefix delegation
      kubectl set env daemonset aws-node -n kube-system ENABLE_PREFIX_DELEGATION=true --kubeconfig <(echo $KUBECONFIG | base64 -d)
      kubectl set env daemonset aws-node -n kube-system WARM_PREFIX_TARGET=1 --kubeconfig <(echo $KUBECONFIG | base64 -d)
    EOT
  }
}

#---------------------------------------------------------------
# VPC-CNI Custom Networking ENIConfig
#---------------------------------------------------------------

resource "kubectl_manifest" "eni_config" {
  for_each = zipmap(local.azs, slice(module.vpc.private_subnets, 3, 6))

  yaml_body = yamlencode({
    apiVersion = "crd.k8s.amazonaws.com/v1alpha1"
    kind       = "ENIConfig"
    metadata = {
      name = each.key
    }
    spec = {
      securityGroups = [
        module.eks_blueprints.cluster_primary_security_group_id,
        module.eks_blueprints.worker_node_security_group_id,
      ]
      subnet = each.value
    }
  })
}

#---------------------------------------------------------------
# Supporting Resources
#---------------------------------------------------------------

data "aws_ssm_parameter" "eks_optimized_ami" {
  name = "/aws/service/eks/optimized-ami/${local.cluster_version}/amazon-linux-2/recommended/image_id"
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 3.0"

  name = local.name
  cidr = local.vpc_cidr

  # secondary_cidr_blocks = [local.secondary_vpc_cidr] # can add up to 5 total CIDR blocks

  azs = local.azs
  # private_subnets = concat(
    # [for k, v in local.azs : cidrsubnet(local.vpc_cidr, 4, k)],
    # [for k, v in local.azs : cidrsubnet(local.secondary_vpc_cidr, 2, k)]
  # )
  private_subnets = [for k, v in local.azs : cidrsubnet(local.vpc_cidr, 4, k)]
  public_subnets = [for k, v in local.azs : cidrsubnet(local.vpc_cidr, 8, k + 48)]
  intra_subnets  = [for k, v in local.azs : cidrsubnet(local.vpc_cidr, 8, k + 52)]

  enable_nat_gateway   = false
  single_nat_gateway   = false
  enable_dns_hostnames = true

  # Manage so we can name
  manage_default_network_acl    = true
  default_network_acl_tags      = { Name = "${local.name}-default" }
  manage_default_route_table    = true
  default_route_table_tags      = { Name = "${local.name}-default" }
  manage_default_security_group = true
  default_security_group_tags   = { Name = "${local.name}-default" }

  public_subnet_tags = {
    "kubernetes.io/cluster/${local.name}" = "shared"
    "kubernetes.io/role/elb"              = 1
  }

  private_subnet_tags = {
    "kubernetes.io/cluster/${local.name}" = "shared"
    "kubernetes.io/role/internal-elb"     = 1
  }

  tags = local.tags
}


module "efs" {
  source  = "terraform-aws-modules/efs/aws"
  version = "~> 1.0"

  creation_token = local.name
  name           = local.name

  # Mount targets / security group
  mount_targets = { for k, v in toset(range(length(local.azs))) :
    element(local.azs, k) => { subnet_id = element(module.vpc.private_subnets, k) }
  }
  security_group_description = "${local.name} EFS security group"
  security_group_vpc_id      = module.vpc.vpc_id
  security_group_rules = {
    vpc = {
      # relying on the defaults provdied for EFS/NFS (2049/TCP + ingress)
      description = "NFS ingress from VPC private subnets"
      cidr_blocks = module.vpc.private_subnets_cidr_blocks
    }
  }

  tags = local.tags
}


resource "kubernetes_storage_class_v1" "efs" {
  metadata {
    name = "efs"
  }

  storage_provisioner = "efs.csi.aws.com"
  reclaim_policy      = "Retain"
  parameters = {
    provisioningMode = "efs-ap" # Dynamic provisioning
    fileSystemId     = module.efs.id
    directoryPerms   = "700"
  }

  mount_options = [
    "iam"
  ]

  depends_on = [
    module.eks_blueprints_kubernetes_addons
  ]
}

module "velero_backup_s3_bucket" {
  source  = "terraform-aws-modules/s3-bucket/aws"
  version = "~> 3.0"

  bucket = "${local.name}-${random_string.random.result}"

  # Allow deletion of non-empty bucket
  # NOTE: This is enabled for example usage only, you should not enable this for production workloads
  force_destroy = true

  attach_deny_insecure_transport_policy = true
  attach_require_latest_tls_policy      = true

  acl = "private"

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true

  control_object_ownership = true
  object_ownership         = "BucketOwnerPreferred"

  versioning = {
    status     = true
    mfa_delete = false
  }

  server_side_encryption_configuration = {
    rule = {
      apply_server_side_encryption_by_default = {
        sse_algorithm = "AES256"
      }
    }
  }

  tags = local.tags
}
resource "random_string" "random" {
  length  = 16
  special = false
  upper   = false
}

# data "aws_route53_zone" "selected" {
#   # name = "tp-packing.com."
#   zone_id = "Z03340993JGGJ7QTM0399"
# }
