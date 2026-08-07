# AWS Access Requirements — Cloud Configuration Review

**Engagement:** Read-only configuration review of the AWS account(s) listed below.
**Tool:** CloudGuard (`cloudsecreview`) — performs **read-only API calls only**; no data is
written, no configuration is changed, and no customer data is read.
**Window:** `<engagement start date>` → `<engagement end date>` (time-bound, see below).

---

## 1. Access requested

We request a **dedicated IAM role/user** scoped for the engagement — never the root
account. The primary recommendation is the AWS-managed **`ReadOnlyAccess`** policy (the
equivalent of Azure's built-in Reader / GCP's Viewer): it covers every service CloudGuard
calls with no blind spots, and an explicit allow-list would produce false negatives (an
ungranted service looks identical to "no findings" in a review report).

| # | Policy / role | Scope | Why it is needed |
|---|---|---|---|
| 1 | **`ReadOnlyAccess`** (managed) — or the scoped policy in §1a | Single account (or each account in scope) | All control-plane reads across the services CloudGuard reviews: S3, EC2, IAM, RDS, CloudTrail, Config, KMS, ECR, Lambda, GuardDuty, Secrets Manager (list only), ACM, SQS, DynamoDB (metadata only), Redshift, EFS, ElastiCache, ELB/ELBv2, EKS, API Gateway, Route53, CloudWatch, CloudFront, WAF-regional, CloudWatch Logs, Backup, ECS, IoT, SES. |
| 2 | *OrganizationViewerAccess* (optional) | Organization root | Only if the review spans multiple accounts and organization-wide posture is in scope (alternatively, deploy the read-only role per account). |

### 1a. Scoped policy (strict alternative to the managed policy)

If your security team prefers an explicit allow-list over the managed policy, this is the
verified minimum matching exactly what CloudGuard calls — all **List/Describe/Get metadata**:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "s3:GetBucket*", "s3:GetAccountPublicAccessBlock", "s3:ListAllMyBuckets",
      "acm:DescribeCertificate", "acm:ListCertificates",
      "apigateway:GET",
      "backup:ListBackupPlans", "backup:ListBackupVaults",
      "cloudfront:GetDistribution", "cloudfront:ListDistributions",
      "cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus",
      "cloudwatch:DescribeAlarms", "cloudwatch:ListDashboards",
      "config:DescribeConfigurationRecorders", "config:DescribeDeliveryChannels",
      "dynamodb:DescribeContinuousBackups", "dynamodb:DescribeTable", "dynamodb:ListTables",
      "ec2:Describe*", "ec2:GetEbsEncryptionByDefault",
      "ecr:DescribeRepositories", "ecr:GetLifecyclePolicy", "ecr:GetRepositoryPolicy",
      "ecs:DescribeClusters", "ecs:DescribeTaskDefinition", "ecs:ListClusters", "ecs:ListTaskDefinitions",
      "efs:DescribeBackupPolicy", "efs:DescribeFileSystems", "efs:DescribeLifecycleConfiguration",
      "eks:DescribeCluster", "eks:ListClusters",
      "elasticache:DescribeCacheClusters",
      "elb:DescribeLoadBalancerAttributes", "elb:DescribeLoadBalancers",
      "elbv2:DescribeListeners", "elbv2:DescribeLoadBalancerAttributes", "elbv2:DescribeLoadBalancers",
      "guardduty:GetDetector", "guardduty:ListDetectors",
      "iam:Get*", "iam:List*",
      "iot:GetLoggingOptions", "iot:GetPolicy", "iot:ListPolicies",
      "kms:Get*", "kms:List*",
      "lambda:GetPolicy", "lambda:ListFunctions",
      "logs:DescribeLogGroups",
      "rds:Describe*",
      "redshift:DescribeClusters", "redshift:DescribeLoggingStatus",
      "route53:GetDnssec", "route53:ListHostedZones", "route53:ListQueryLoggingConfigs",
      "secretsmanager:ListSecrets",
      "ses:GetIdentityDkimAttributes", "ses:ListIdentities",
      "sns:Get*", "sns:List*",
      "sqs:GetQueueAttributes", "sqs:ListQueues",
      "sts:GetCallerIdentity",
      "waf-regional:ListResourcesForWebACL", "waf-regional:ListWebACLs"
    ],
    "Resource": "*"
  }]
}
```

## 2. What we explicitly do NOT request

Stating exclusions is deliberate — it defines the blast radius of this access:

- ❌ `s3:GetObject` / `s3:GetObjectVersion` (no object data — bucket metadata only)
- ❌ `secretsmanager:GetSecretValue` (secret names/metadata only via `ListSecrets`)
- ❌ `kms:Decrypt` / `kms:GenerateDataKey` (no key material)
- ❌ `dynamodb:GetItem` / `Query` / `Scan` (no table data)
- ❌ `ssm:GetParameter` / `GetParameters` (not used)
- ❌ Any `Put*`, `Delete*`, `Create*` or `Manage*` action

No identity used in this engagement will hold an administrative policy, and the root
account is never used.

## 3. Time-bound assignment

> "Access is granted for the engagement window only (`<start>` → `<end>`). The role is
> scoped with an **external ID** and, where possible, issued as **temporary credentials**
> (role session with a limited duration) rather than a long-lived access key. All
> credentials/keys are revoked no later than `<end date>`."

## 4. Recommended deployment pattern

- **Single engagement:** a cross-account IAM role in the target account(s) trusting the
  consultancy's account with an **external ID**, assuming the managed `ReadOnlyAccess`
  policy — no user accounts created in the client environment.
- **Multi-account engagement:** the same role deployed per account (via CloudFormation
  StackSet or the organization's standard mechanism), or `OrganizationViewerAccess`
  where organization-wide posture is in scope.
- **Recurring engagements:** the same role pattern with automated credential rotation.

## 5. Verification

After provisioning, CloudGuard's built-in privilege self-check
(`python3 run.py scan --cloud aws --profile <profile>`) confirms the principal is
read-only and reports over-privilege (e.g. root or admin policies) before scanning
begins. The least-privilege reference used at scan time is printed by
`python3 run.py policies --cloud aws`.
