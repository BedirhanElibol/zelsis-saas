import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

/** CLOUD-V2: cloud / IaC / Kubernetes / container misconfiguration. Each `ignores` is the fixed version. */
export const CASES: RuleCase[] = [
  {
    ruleIds: [28501],
    name: 'CLOUD-V2-01: RDS storage encryption explicitly disabled',
    detects: f('infra/db.tf', `resource "aws_db_instance" "main" {
  identifier        = "app-db"
  engine            = "postgres"
  instance_class    = "db.t3.micro"
  allocated_storage = 20
  storage_encrypted = false
  username          = "app"
  password          = var.db_password
}
`),
    ignores: f('infra/db.tf', `resource "aws_db_instance" "main" {
  identifier        = "app-db"
  engine            = "postgres"
  instance_class    = "db.t3.micro"
  allocated_storage = 20
  storage_encrypted = true
  username          = "app"
  password          = var.db_password
}
`),
  },
  {
    ruleIds: [28502],
    name: 'CLOUD-V2-02: Redshift cluster publicly accessible',
    detects: f('infra/warehouse.tf', `resource "aws_redshift_cluster" "analytics" {
  cluster_identifier  = "analytics"
  node_type           = "dc2.large"
  master_username     = "admin"
  master_password     = var.redshift_password
  publicly_accessible = true
  encrypted           = true
}
`),
    ignores: f('infra/warehouse.tf', `resource "aws_redshift_cluster" "analytics" {
  cluster_identifier  = "analytics"
  node_type           = "dc2.large"
  master_username     = "admin"
  master_password     = var.redshift_password
  publicly_accessible = false
  encrypted           = true
}
`),
  },
  {
    ruleIds: [28503],
    name: 'CLOUD-V2-03: IAM role assumable by any AWS principal',
    detects: f('infra/iam.tf', `data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
  }
}

resource "aws_iam_role" "deployer" {
  name               = "deployer"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}
`),
    ignores: f('infra/iam.tf', `data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::123456789012:root"]
    }
  }
}

resource "aws_iam_role" "deployer" {
  name               = "deployer"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}
`),
  },
  {
    ruleIds: [28503],
    name: 'CLOUD-V2-03: inline trust policy with Principal AWS "*"',
    detects: f('infra/role.tf', `resource "aws_iam_role" "ci" {
  name = "ci"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { AWS = "*" }
    }]
  })
}
`),
    ignores: f('infra/role.tf', `resource "aws_iam_role" "ci" {
  name = "ci"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { AWS = "*" }
      Condition = { StringEquals = { "aws:PrincipalOrgID" = var.org_id } }
    }]
  })
}
`),
  },
  {
    ruleIds: [28504],
    name: 'CLOUD-V2-04: Lambda permission for principal "*"',
    detects: f('infra/lambda.tf', `resource "aws_lambda_permission" "allow_invoke" {
  statement_id  = "AllowInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.thumbnail.function_name
  principal     = "*"
}
`),
    ignores: f('infra/lambda.tf', `resource "aws_lambda_permission" "allow_invoke" {
  statement_id   = "AllowS3Invoke"
  action         = "lambda:InvokeFunction"
  function_name  = aws_lambda_function.thumbnail.function_name
  principal      = "s3.amazonaws.com"
  source_arn     = aws_s3_bucket.uploads.arn
  source_account = data.aws_caller_identity.current.account_id
}
`),
  },
  {
    ruleIds: [28505],
    name: 'CLOUD-V2-05: SQS queue policy open to everyone',
    detects: f('infra/queue.tf', `resource "aws_sqs_queue_policy" "jobs" {
  queue_url = aws_sqs_queue.jobs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.jobs.arn
    }]
  })
}
`),
    ignores: f('infra/queue.tf', `resource "aws_sqs_queue_policy" "jobs" {
  queue_url = aws_sqs_queue.jobs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "sns.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.jobs.arn
    }]
  })
}
`),
  },
  {
    ruleIds: [28506],
    name: 'CLOUD-V2-06: GCP firewall SSH from 0.0.0.0/0',
    detects: f('infra/gcp/network.tf', `resource "google_compute_firewall" "ssh" {
  name    = "allow-ssh"
  network = google_compute_network.main.name

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["0.0.0.0/0"]
}
`),
    ignores: f('infra/gcp/network.tf', `resource "google_compute_firewall" "ssh" {
  name    = "allow-ssh-iap"
  network = google_compute_network.main.name

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["35.235.240.0/20"]
}
`),
  },
  {
    ruleIds: [28507],
    name: 'CLOUD-V2-07: Azure NSG RDP from Internet',
    detects: f('infra/azure/nsg.tf', `resource "azurerm_network_security_group" "vm" {
  name                = "vm-nsg"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  security_rule {
    name                       = "rdp"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}
`),
    ignores: f('infra/azure/nsg.tf', `resource "azurerm_network_security_group" "vm" {
  name                = "vm-nsg"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  security_rule {
    name                       = "https"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}
`),
  },
  {
    ruleIds: [28508],
    name: 'CLOUD-V2-08: Cloud SQL authorized network 0.0.0.0/0',
    detects: f('infra/gcp/sql.tf', `resource "google_sql_database_instance" "main" {
  name             = "app-db"
  database_version = "POSTGRES_15"

  settings {
    tier = "db-f1-micro"
    ip_configuration {
      ipv4_enabled = true
      authorized_networks {
        name  = "anywhere"
        value = "0.0.0.0/0"
      }
    }
  }
}
`),
    ignores: f('infra/gcp/sql.tf', `resource "google_sql_database_instance" "main" {
  name             = "app-db"
  database_version = "POSTGRES_15"

  settings {
    tier = "db-f1-micro"
    ip_configuration {
      ipv4_enabled    = false
      private_network = google_compute_network.main.id
    }
  }
}
`),
  },
  {
    ruleIds: [28509],
    name: 'CLOUD-V2-09: Azure SQL firewall allows all IPv4',
    detects: f('infra/azure/sql.tf', `resource "azurerm_mssql_firewall_rule" "all" {
  name             = "allow-all"
  server_id        = azurerm_mssql_server.main.id
  start_ip_address = "0.0.0.0"
  end_ip_address   = "255.255.255.255"
}
`),
    ignores: f('infra/azure/sql.tf', `resource "azurerm_mssql_firewall_rule" "azure_services" {
  name             = "allow-azure-services"
  server_id        = azurerm_mssql_server.main.id
  start_ip_address = "0.0.0.0"
  end_ip_address   = "0.0.0.0"
}
`),
  },
  {
    ruleIds: [28510],
    name: 'CLOUD-V2-10: Azure container anonymous listing',
    detects: f('infra/azure/storage.tf', `resource "azurerm_storage_container" "uploads" {
  name                  = "uploads"
  storage_account_name  = azurerm_storage_account.main.name
  container_access_type = "container"
}
`),
    ignores: f('infra/azure/storage.tf', `resource "azurerm_storage_container" "uploads" {
  name                  = "uploads"
  storage_account_name  = azurerm_storage_account.main.name
  container_access_type = "private"
}
`),
  },
  {
    ruleIds: [28511],
    name: 'CLOUD-V2-11: GCS bucket admin granted to allUsers',
    detects: f('infra/gcp/bucket.tf', `resource "google_storage_bucket_iam_member" "public" {
  bucket = google_storage_bucket.assets.name
  role   = "roles/storage.objectAdmin"
  member = "allUsers"
}
`),
    ignores: f('infra/gcp/bucket.tf', `resource "google_storage_bucket_iam_member" "public" {
  bucket = google_storage_bucket.assets.name
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}
`),
  },
  {
    ruleIds: [28512],
    name: 'CLOUD-V2-12: Azure storage account min TLS 1.0',
    detects: f('infra/azure/account.tf', `resource "azurerm_storage_account" "main" {
  name                     = "appstorage"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  min_tls_version          = "TLS1_0"
}
`),
    ignores: f('infra/azure/account.tf', `resource "azurerm_storage_account" "main" {
  name                     = "appstorage"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  min_tls_version          = "TLS1_2"
}
`),
  },
  {
    ruleIds: [28513],
    name: 'CLOUD-V2-13: GKE legacy ABAC enabled',
    detects: f('infra/gcp/gke.tf', `resource "google_container_cluster" "primary" {
  name               = "primary"
  location           = "europe-west1"
  initial_node_count = 1
  enable_legacy_abac = true
}
`),
    ignores: f('infra/gcp/gke.tf', `resource "google_container_cluster" "primary" {
  name               = "primary"
  location           = "europe-west1"
  initial_node_count = 1
  enable_legacy_abac = false
}
`),
  },
  {
    ruleIds: [28514],
    name: 'CLOUD-V2-14: ClusterRole with */* rules',
    detects: f('deploy/k8s/rbac.yaml', `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: app-controller
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]
`),
    ignores: f('deploy/k8s/rbac.yaml', `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: app-controller
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get", "list", "watch"]
`),
  },
  {
    ruleIds: [28515],
    name: 'CLOUD-V2-15: binding to system:anonymous',
    detects: f('deploy/k8s/binding.yaml', `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: public-read
subjects:
  - kind: User
    name: system:anonymous
    apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: view
  apiGroup: rbac.authorization.k8s.io
`),
    ignores: f('deploy/k8s/binding.yaml', `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: public-read
subjects:
  - kind: Group
    name: platform-readers
    apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: view
  apiGroup: rbac.authorization.k8s.io
`),
  },
  {
    ruleIds: [28516],
    name: 'CLOUD-V2-16: cluster-admin bound to app ServiceAccount',
    detects: f('deploy/k8s/sa.yaml', `apiVersion: v1
kind: ServiceAccount
metadata:
  name: api
  namespace: app
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: api-admin
subjects:
  - kind: ServiceAccount
    name: api
    namespace: app
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
`),
    ignores: f('deploy/k8s/sa.yaml', `apiVersion: v1
kind: ServiceAccount
metadata:
  name: api
  namespace: app
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: api-config-reader
  namespace: app
subjects:
  - kind: ServiceAccount
    name: api
    namespace: app
roleRef:
  kind: Role
  name: config-reader
  apiGroup: rbac.authorization.k8s.io
`),
  },
  {
    ruleIds: [28517, 28518],
    name: 'CLOUD-V2-17/18: privilege escalation allowed and seccomp unconfined',
    detects: f('deploy/k8s/deployment.yaml', `apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  template:
    spec:
      containers:
        - name: api
          image: ghcr.io/acme/api:1.4.2
          securityContext:
            allowPrivilegeEscalation: true
            seccompProfile:
              type: Unconfined
`),
    ignores: f('deploy/k8s/deployment.yaml', `apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  template:
    spec:
      containers:
        - name: api
          image: ghcr.io/acme/api:1.4.2
          securityContext:
            allowPrivilegeEscalation: false
            seccompProfile:
              type: RuntimeDefault
`),
  },
  {
    ruleIds: [28519],
    name: 'CLOUD-V2-19: plaintext DB password in env value',
    detects: f('deploy/k8s/worker.yaml', `apiVersion: apps/v1
kind: Deployment
metadata:
  name: worker
spec:
  template:
    spec:
      containers:
        - name: worker
          image: ghcr.io/acme/worker:2.0.0
          env:
            - name: DATABASE_HOST
              value: postgres.app.svc
            - name: DATABASE_PASSWORD
              value: "Tr0ub4dor-prod-2024"
`),
    ignores: f('deploy/k8s/worker.yaml', `apiVersion: apps/v1
kind: Deployment
metadata:
  name: worker
spec:
  template:
    spec:
      containers:
        - name: worker
          image: ghcr.io/acme/worker:2.0.0
          env:
            - name: DATABASE_HOST
              value: postgres.app.svc
            - name: DATABASE_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: worker-db
                  key: password
`),
  },
  {
    ruleIds: [28520],
    name: 'CLOUD-V2-20: Dockerfile curl over http piped to sh',
    detects: f('Dockerfile', `FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y curl \\
    && curl -fsSL http://get.example-tools.io/install.sh | sh
USER app
`),
    ignores: f('Dockerfile', `FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y curl \\
    && curl -fsSLo /tmp/install.sh https://get.example-tools.io/install.sh \\
    && echo "3f1c2d0e9a  /tmp/install.sh" | sha256sum -c - && sh /tmp/install.sh
USER app
`),
  },
  {
    ruleIds: [28521],
    name: 'CLOUD-V2-21: ADD from plain HTTP',
    detects: f('docker/api.Dockerfile', `FROM node:20-alpine
ADD http://downloads.example.com/geoip/GeoLite2-City.mmdb /app/data/
COPY . /app
`),
    ignores: f('docker/api.Dockerfile', `FROM node:20-alpine
ADD --checksum=sha256:24454f830cdb571e2c4ad15481119c43b3cafd48dd869a9b2945d1036d1dc68d https://downloads.example.com/geoip/GeoLite2-City.mmdb /app/data/
COPY . /app
`),
  },
  {
    ruleIds: [28522, 28523, 28518],
    name: 'CLOUD-V2-22/23/18: compose host namespaces and seccomp unconfined',
    detects: f('docker-compose.yml', `services:
  agent:
    image: acme/monitor-agent:3.1
    pid: host
    network_mode: host
    security_opt:
      - seccomp:unconfined
`),
    ignores: f('docker-compose.yml', `services:
  agent:
    image: acme/monitor-agent:3.1
    networks:
      - internal
    ports:
      - "127.0.0.1:9100:9100"
networks:
  internal: {}
`),
  },
  {
    ruleIds: [28524],
    name: 'CLOUD-V2-24: Docker API published on 2375',
    detects: f('docker-compose.ci.yml', `services:
  docker:
    image: docker:27-dind
    privileged: true
    command: ["dockerd", "-H", "unix:///var/run/docker.sock", "--host=tcp://0.0.0.0:2375"]
    ports:
      - "2375:2375"
`),
    ignores: f('docker-compose.ci.yml', `services:
  docker:
    image: docker:27-dind
    privileged: true
    environment:
      DOCKER_TLS_CERTDIR: /certs
    volumes:
      - docker-certs:/certs
volumes:
  docker-certs: {}
`),
  },
  {
    ruleIds: [28525],
    name: 'CLOUD-V2-25: kubelet anonymous auth and AlwaysAllow',
    detects: f('infra/kubelet/config.yaml', `apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
authentication:
  anonymous:
    enabled: true
authorization:
  mode: AlwaysAllow
`),
    ignores: f('infra/kubelet/config.yaml', `apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
authentication:
  anonymous:
    enabled: false
  webhook:
    enabled: true
authorization:
  mode: Webhook
`),
  },
];
