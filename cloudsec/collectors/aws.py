"""AWS collector (boto3). Requires the AWS SDK and valid credentials.

Auth options (``auth`` dict):
  profile: str       - boto3 profile name (defaults to env/default chain)
  region: str        - primary region (default us-east-1)
  regions: [str]     - override region list
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List


def collect_aws(auth: Dict[str, Any]) -> tuple[Dict[str, Any], List[Dict[str, Any]]]:
    import boto3  # lazy

    errors: List[Dict[str, Any]] = []
    profile = auth.get("profile")
    regions = auth.get("regions") or [auth.get("region") or "us-east-1"]
    session = boto3.Session(profile_name=profile) if profile else boto3.Session()
    sts = session.client("sts", region_name=regions[0])
    identity = sts.get_caller_identity()
    account_id = identity["Account"]
    principal = identity["Arn"]

    snapshot: Dict[str, Any] = {
        "account_id": account_id,
        "principal": principal,
        "iam": {"password_policy": None, "root": {}, "users": [], "admin_policies": [],
                 "cross_account_roles": []},
        "s3": [], "rds": [], "sns": [], "trail": {}, "config": {},
        "kms": [], "ecr": [], "lambda": [],
        "ec2": {"security_groups": [], "volumes": [], "instances": [], "amis": [],
                 "ebs_default_encryption": False, "default_sg_open": False},
        "vpcs": [], "nacls": [], "guardduty": [], "secrets": [],
        "sqs": [], "dynamodb": [], "redshift": [], "efs": [],
        "elasticache": [], "elb": [], "acm": [], "eks": [],
        "apigw": [], "r53": {"dnssec": False, "query_logging": False,
                              "zone_count": 0},
        "cw": {"metric_alarms": [], "dashboards": 0},
        "cloudfront": [], "loggroups": [], "snapshots": [],
        "backup": {"plans": 0, "vaults": 0},
        "rds_public_snapshots": False, "elb_classic": [],
        "ecs": {"clusters": [], "task_definitions": []},
        "iot": {"logging_level": None, "public_policies": []},
        "ses": {"identities": [], "dkim_unverified": []},
    }

    def note(service: str, err: Exception, ctx: str = "") -> None:
        errors.append({"service": service, "error": str(err)[:300], "context": ctx})

    iam = session.client("iam", region_name=regions[0])
    try:
        pp = iam.get_account_password_policy().get("PasswordPolicy", {})
        snapshot["iam"]["password_policy"] = {
            "minimum_password_length": pp.get("MinimumPasswordLength"),
            "require_symbols": pp.get("RequireSymbols"),
            "require_numbers": pp.get("RequireNumbers"),
            "require_uppercase_characters": pp.get("RequireUppercaseCharacters"),
            "require_lowercase_characters": pp.get("RequireLowercaseCharacters"),
            "max_password_age": pp.get("MaxPasswordAge"),
        }
    except Exception as e:  # NoSuchEntity -> no policy
        snapshot["iam"]["password_policy"] = None
    try:
        summary = iam.get_account_summary()["SummaryMap"]
        snapshot["iam"]["root"] = {
            "access_keys_active": bool(summary.get("AccountAccessKeysPresent", 0)),
            "access_key_count": int(summary.get("AccountAccessKeysPresent", 0)),
            "mfa_enabled": bool(summary.get("AccountMFAEnabled", 0)),
        }
    except Exception as e:
        note("iam", e, "get_account_summary")
    try:
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for u in page["Users"]:
                user = {"name": u["UserName"], "has_console_password": False,
                        "mfa_enabled": False, "keys": []}
                try:
                    iam.get_login_profile(UserName=u["UserName"])
                    user["has_console_password"] = True
                except Exception:
                    pass
                try:
                    devs = iam.list_mfa_devices(UserName=u["UserName"])["MFADevices"]
                    user["mfa_enabled"] = bool(devs)
                except Exception:
                    pass
                try:
                    for k in iam.list_access_keys(UserName=u["UserName"])["AccessKeyMetadata"]:
                        age = 0
                        if k.get("CreateDate"):
                            created = k["CreateDate"]
                            if created.tzinfo is None:  # botocore may return naive UTC
                                created = created.replace(tzinfo=timezone.utc)
                            age = max(0, (datetime.now(timezone.utc) - created).days)
                        user["keys"].append({
                            "id": k["AccessKeyId"],
                            "age_days": age,
                            "active": k["Status"] == "Active",
                        })
                except Exception as e:
                    note("iam", e, f"list_access_keys:{u['UserName']}")
                snapshot["iam"]["users"].append(user)
    except Exception as e:
        note("iam", e, "list_users")
    try:
        for role in iam.list_roles().get("Roles", []):
            doc = role.get("AssumeRolePolicyDocument") or {}
            stmts = doc.get("Statement", [])
            if isinstance(stmts, dict):
                stmts = [stmts]
            external = False
            for st in stmts:
                pr = st.get("Principal", {})
                if isinstance(pr, str):
                    pr = {"AWS": pr}
                aws = pr.get("AWS", [])
                if isinstance(aws, str):
                    aws = [aws]
                for a in aws:
                    a = str(a)
                    if a == "*" or (":root" in a and account_id not in a):
                        external = True
            if external:
                snapshot["iam"]["cross_account_roles"].append(role["RoleName"])
    except Exception as e:
        note("iam", e, "list_roles")

    # Admin-policy scan: flag only policies that actually grant *:* or "*" actions.
    def _is_admin_doc(doc: Any) -> bool:
        stmts = doc.get("Statement", [])
        if isinstance(stmts, dict):
            stmts = [stmts]
        for st in stmts:
            action = st.get("Action")
            if isinstance(action, str):
                action = [action]
            if action and any(a in ("*", "*:*") for a in action):
                return True
        return False

    try:
        details = iam.get_account_authorization_details(
            Filter=["LocalManagedPolicy", "AWSManagedPolicy", "User", "Role", "Group"])
        seen: set = set()
        for pol in details.get("Policies", []):
            pname = pol["PolicyName"]
            versions = pol.get("PolicyVersionList", [])
            if pname in seen:
                continue
            if versions and _is_admin_doc(versions[0].get("Document", {})):
                snapshot["iam"]["admin_policies"].append(pname)
                seen.add(pname)
        for entity in (details.get("UserDetailList", []) + details.get("RoleDetailList", [])
                       + details.get("GroupDetailList", [])):
            for p in entity.get("AttachedManagedPolicies", []):
                if p["PolicyName"] in ("AdministratorAccess", "PowerUserAccess"):
                    if p["PolicyName"] not in seen:
                        snapshot["iam"]["admin_policies"].append(p["PolicyName"])
                        seen.add(p["PolicyName"])
    except Exception as e:
        note("iam", e, "admin-policy-scan")

    # S3
    try:
        s3 = session.client("s3", region_name=regions[0])
        for b in s3.list_buckets().get("Buckets", []):
            name = b["Name"]
            entry = {"name": name, "public": False, "public_acl": None,
                     "encryption": False, "versioning": False, "logging": False,
                     "mfa_delete": False}
            try:
                pab = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
                if not (pab.get("BlockPublicAcls") and pab.get("BlockPublicPolicy")
                        and pab.get("IgnorePublicAcls") and pab.get("RestrictPublicBuckets")):
                    entry["public"] = True
            except Exception:
                pass  # no PAB => not protected => flagged by public check only if policy/ACL open
            try:
                acl = s3.get_bucket_acl(Bucket=name)["Grants"]
                for g in acl:
                    if g.get("Grantee", {}).get("URI", "").endswith("AllUsers"):
                        entry["public"] = True
                        entry["public_acl"] = "AllUsers"
                    if g.get("Grantee", {}).get("URI", "").endswith("AuthenticatedUsers"):
                        entry["public_acl"] = "AuthenticatedUsers"
            except Exception:
                pass
            try:
                pol = s3.get_bucket_policy(Bucket=name)["Policy"]
                if '"*"' in pol:
                    entry["public"] = True
            except Exception:
                pass
            try:
                s3.get_bucket_encryption(Bucket=name)
                entry["encryption"] = True
            except Exception:
                entry["encryption"] = False
            try:
                v = s3.get_bucket_versioning(Bucket=name)
                entry["versioning"] = bool(v.get("Status"))
                entry["mfa_delete"] = v.get("MfaDelete") == "Enabled"
            except Exception:
                pass
            try:
                entry["logging"] = bool(s3.get_bucket_logging(Bucket=name).get("LoggingEnabled"))
            except Exception:
                pass
            snapshot["s3"].append(entry)
    except Exception as e:
        note("s3", e, "list_buckets")

    # EC2 / network (all requested regions; per-region try so one bad
    # region does not kill coverage for the others)
    for region in regions:
        try:
            ec2 = session.client("ec2", region_name=region)
            for sg in ec2.describe_security_groups()["SecurityGroups"]:
                ingress = []
                for perm in sg.get("IpPermissions", []):
                    proto = perm.get("IpProtocol", "-1")
                    lo = perm.get("FromPort")
                    hi = perm.get("ToPort")
                    cidrs = [r.get("CidrIp") for r in perm.get("IpRanges", []) if r.get("CidrIp")]
                    cidrs += [r.get("CidrIpv6") for r in perm.get("Ipv6Ranges", []) if r.get("CidrIpv6")]
                    ingress.append({"proto": proto, "ports": (lo, hi) if lo is not None else None,
                                    "cidr": cidrs})
                snapshot["ec2"]["security_groups"].append({
                    "id": sg["GroupId"], "name": sg["GroupName"], "ingress": ingress})
            for v in ec2.describe_volumes()["Volumes"]:
                snapshot["ec2"]["volumes"].append({"id": v["VolumeId"], "encrypted": v["Encrypted"]})
            for res in ec2.describe_instances()["Reservations"]:
                for i in res["Instances"]:
                    pub_ip = i.get("PublicIpAddress")
                    snapshot["ec2"]["instances"].append({
                        "id": i["InstanceId"], "public_ip": pub_ip,
                        "security_groups": [g["GroupId"] for g in i.get("SecurityGroups", [])]})
            for image in ec2.describe_images(Owners=["self"])["Images"]:
                snapshot["ec2"]["amis"].append({"id": image["ImageId"], "public": image.get("Public")})
        except Exception as e:
            note("ec2", e, f"describe_* @{region}")

    # RDS (all requested regions)
    for region in regions:
        try:
            rds = session.client("rds", region_name=region)
            for db in rds.describe_db_instances()["DBInstances"]:
                snapshot["rds"].append({
                    "id": db["DBInstanceIdentifier"],
                    "publicly_accessible": db.get("PubliclyAccessible", False),
                    "storage_encrypted": db.get("StorageEncrypted", False),
                    "backup_retention_days": db.get("BackupRetentionPeriod", 0),
                    "deletion_protection": bool(db.get("DeletionProtection")),
                    "multi_az": bool(db.get("MultiAZ")),
                    "minor_version": db.get("EngineVersion", ""),
                    "log_exports": bool(db.get("EnabledCloudwatchLogsExports")),
                    "auto_minor_upgrade": bool(db.get("AutoMinorVersionUpgrade")),
                })
        except Exception as e:
            note("rds", e, f"describe_db_instances @{region}")

    # SNS
    try:
        sns = session.client("sns", region_name=regions[0])
        for t in sns.list_topics().get("Topics", []):
            arn = t["TopicArn"]
            public = False
            try:
                attrs = sns.get_topic_attributes(TopicArn=arn)["Attributes"]
                pol = attrs.get("Policy", "")
                if ('"*"' in pol and 'sns:Publish' in pol) or ('"*"' in pol and 'sns:Subscribe' in pol):
                    public = True
            except Exception:
                pass
            snapshot["sns"].append({"topic_arn": arn, "public": public,
                                    "kms_encrypted": bool(attrs.get("KmsMasterKeyId"))})
    except Exception as e:
        note("sns", e, "list_topics")

    # CloudTrail
    try:
        ct = session.client("cloudtrail", region_name=regions[0])
        trails = ct.describe_trails()["trailList"]
        if trails:
            status = ct.get_trail_status(Name=trails[0]["TrailARN"])
            bucket_encrypted = False
            bucket = trails[0].get("S3BucketName")
            if bucket:
                try:
                    s3c = session.client("s3", region_name=regions[0])
                    s3c.get_bucket_encryption(Bucket=bucket)
                    bucket_encrypted = True
                except Exception:
                    pass
            snapshot["trail"] = {
                "exists": True,
                "multi_region": bool(trails[0].get("IsMultiRegionTrail")),
                "log_file_validation": bool(trails[0].get("LogFileValidationEnabled")),
                "logging": status.get("IsLogging", False),
                "s3_bucket_encrypted": bucket_encrypted,
                "kms_key_id": bool(trails[0].get("KmsKeyId")),
            }
        else:
            snapshot["trail"] = {"exists": False, "multi_region": False,
                                 "log_file_validation": False,
                                 "s3_bucket_encrypted": False, "kms_key_id": False}
    except Exception as e:
        note("cloudtrail", e, "describe_trails")

    # Config
    try:
        cfg = session.client("config", region_name=regions[0])
        recorders = cfg.describe_configuration_recorders()["ConfigurationRecorders"]
        channels = cfg.describe_delivery_channels()["DeliveryChannels"]
        snapshot["config"] = {"recorder": bool(recorders),
                              "delivering": bool(channels)}
    except Exception as e:
        note("config", e, "describe_configuration_recorders")

    # KMS / ECR / Lambda (all requested regions)
    for region in regions:
        try:
            kms = session.client("kms", region_name=region)
            for k in kms.list_keys()["Keys"]:
                kid = k["KeyId"]
                try:
                    rotation = kms.get_key_rotation_status(KeyId=kid)["KeyRotationEnabled"]
                except Exception:
                    rotation = False
                snapshot["kms"].append({"key_id": kid, "rotation_enabled": rotation})
        except Exception as e:
            note("kms", e, f"list_keys @{region}")
    for region in regions:
        try:
            ecr = session.client("ecr", region_name=region)
            for repo in ecr.describe_repositories()["repositories"]:
                public = False
                try:
                    pol = ecr.get_repository_policy(repositoryName=repo["repositoryName"])
                    if '"*"' in pol.get("policyText", ""):
                        public = True
                except Exception:
                    pass
                scan_on_push = bool((repo.get("ImageScanningConfiguration") or {}).get("scanOnPush"))
                has_lifecycle = False
                try:
                    ecr.get_lifecycle_policy(repositoryName=repo["repositoryName"])
                    has_lifecycle = True
                except Exception:
                    pass
                snapshot["ecr"].append({"repo_name": repo["repositoryName"], "public": public,
                                         "scan_on_push": scan_on_push,
                                         "lifecycle_policy": has_lifecycle})
        except Exception as e:
            note("ecr", e, f"describe_repositories @{region}")
    for region in regions:
        try:
            lam = session.client("lambda", region_name=region)
            for fn in lam.list_functions()["Functions"]:
                public_policy = False
                try:
                    pol = lam.get_policy(FunctionName=fn["FunctionName"])["Policy"]
                    if '"*"' in pol and "lambda:InvokeFunction" in pol:
                        public_policy = True
                except Exception:
                    pass
                vpc = bool(fn.get("VpcConfig") and fn["VpcConfig"].get("SubnetIds"))
                tracing = (fn.get("TracingConfig") or {}).get("Mode") == "Active"
                snapshot["lambda"].append({"name": fn["FunctionName"], "runtime": fn.get("Runtime"),
                                            "public_policy": public_policy, "in_vpc": vpc,
                                            "tracing": tracing})
        except Exception as e:
            note("lambda", e, f"list_functions @{region}")

    # ---- VPCs / flow logs / NACLs / default SG / EBS default encryption ----------
    for region in regions:
        try:
            ec2 = session.client("ec2", region_name=region)
            for vpc in ec2.describe_vpcs()["Vpcs"]:
                is_default = bool(vpc.get("IsDefault"))
                flow = False
                try:
                    fl = ec2.describe_flow_logs(
                        Filters=[{"Name": "resource-id", "Values": [vpc["VpcId"]]}])["FlowLogs"]
                    flow = any(f.get("FlowLogStatus") == "ACTIVE" for f in fl)
                except Exception:
                    pass
                igw = False
                try:
                    igw = bool(ec2.describe_internet_gateways(
                        Filters=[{"Name": "attachment.vpc-id", "Values": [vpc["VpcId"]]}])["InternetGateways"])
                except Exception:
                    pass
                snapshot["vpcs"].append({"id": vpc["VpcId"], "is_default": is_default,
                                          "flow_logs": flow, "has_igw": igw})
            for nacl in ec2.describe_network_acls()["NetworkAcls"]:
                open_all = False
                for e in nacl.get("Entries", []):
                    if e.get("Egress"):
                        continue
                    if e.get("CidrBlock") in ("0.0.0.0/0", "::/0") and e.get("RuleAction") == "allow":
                        if e.get("Protocol") == "-1" or (e.get("PortRange") is None
                                                          and int(e.get("Protocol", 6)) == 6):
                            open_all = True
                snapshot["nacls"].append({"id": nacl["NetworkAclId"], "open_all": open_all})
            # default security group + EBS default encryption
            for sg in ec2.describe_security_groups(
                    Filters=[{"Name": "group-name", "Values": ["default"]}])["SecurityGroups"]:
                for perm in sg.get("IpPermissions", []):
                    for r in perm.get("IpRanges", []) + perm.get("Ipv6Ranges", []):
                        if r.get("CidrIp") in ("0.0.0.0/0", "::/0") or r.get("CidrIpv6") in ("0.0.0.0/0", "::/0"):
                            snapshot["ec2"]["default_sg_open"] = True
            try:
                acct = ec2.get_ebs_encryption_by_default()
                snapshot["ec2"]["ebs_default_encryption"] = bool(acct.get("EbsEncryptionByDefault"))
            except Exception:
                pass
        except Exception as e:
            note("ec2", e, f"vpc/nacl/default-sg @{region}")

    # instance-level hardening fields (IMDSv2, termination protection, monitoring)
    for region in regions:
        try:
            ec2 = session.client("ec2", region_name=region)
            for res in ec2.describe_instances()["Reservations"]:
                for i in res["Instances"]:
                    imds = i.get("MetadataOptions", {}).get("HttpTokens") == "required"
                    prot = False
                    try:
                        attr = ec2.describe_instance_attribute(
                            InstanceId=i["InstanceId"], Attribute="disableApiTermination")
                        prot = bool(attr.get("DisableApiTermination", {}).get("Value"))
                    except Exception:
                        pass
                    mon = i.get("Monitoring", {}).get("State") == "enabled"
                    entry = next((x for x in snapshot["ec2"]["instances"]
                                  if x["id"] == i["InstanceId"]), None)
                    if entry is None:
                        entry = {"id": i["InstanceId"], "public_ip": i.get("PublicIpAddress"),
                                 "security_groups": [g["GroupId"] for g in i.get("SecurityGroups", [])]}
                        snapshot["ec2"]["instances"].append(entry)
                    entry["imdsv2"] = imds
                    entry["termination_protection"] = prot
                    entry["monitoring"] = mon
        except Exception as e:
            note("ec2", e, f"instance-hardening @{region}")

    # ---- GuardDuty / Secrets Manager / ACM (all regions) ---------------------------
    for region in regions:
        try:
            gd = session.client("guardduty", region_name=region)
            for d in gd.list_detectors()["DetectorIds"]:
                try:
                    status = gd.get_detector(DetectorId=d).get("Status") == "ENABLED"
                except Exception:
                    status = True
                snapshot["guardduty"].append({"id": d, "enabled": status})
        except Exception as e:
            note("guardduty", e, f"list_detectors @{region}")
    for region in regions:
        try:
            sm = session.client("secretsmanager", region_name=region)
            for s in sm.list_secrets()["SecretList"]:
                snapshot["secrets"].append({"name": s["Name"],
                                             "rotation_enabled": bool(s.get("RotationEnabled"))})
        except Exception as e:
            note("secretsmanager", e, f"list_secrets @{region}")
    for region in regions:
        try:
            acm = session.client("acm", region_name=region)
            for cert in acm.list_certificates()["CertificateSummaryList"]:
                try:
                    detail = acm.describe_certificate(CertificateArn=cert["CertificateArn"])
                    d = detail["Certificate"]
                    expiry = (d.get("NotAfter") - datetime.now(timezone.utc)).days if d.get("NotAfter") else 9999
                    in_use = bool(d.get("InUseBy"))
                    snapshot["acm"].append({"arn": cert["CertificateArn"], "in_use": in_use,
                                             "days_to_expiry": max(-1, expiry)})
                except Exception:
                    continue
        except Exception as e:
            note("acm", e, f"list_certificates @{region}")

    # ---- SQS / DynamoDB / Redshift / EFS / ElastiCache (all regions) -------------------
    for region in regions:
        try:
            sqs = session.client("sqs", region_name=region)
            for q in sqs.list_queues().get("QueueUrls", []):
                attrs = sqs.get_queue_attributes(QueueUrl=q, AttributeNames=["All"])["Attributes"]
                pol = attrs.get("Policy", "")
                public = '"*"' in pol and "sqs:SendMessage" in pol
                enc = attrs.get("SqsManagedSseEnabled") == "true" or bool(attrs.get("KmsMasterKeyId"))
                snapshot["sqs"].append({"url": q, "public": public, "encrypted": enc,
                                         "has_dlq": bool(attrs.get("RedrivePolicy"))})
        except Exception as e:
            note("sqs", e, f"list_queues @{region}")
    for region in regions:
        try:
            ddb = session.client("dynamodb", region_name=region)
            for t in ddb.list_tables()["TableNames"]:
                desc = ddb.describe_table(TableName=t)["Table"]
                pitr = False
                try:
                    pitr = bool(ddb.describe_continuous_backups(TableName=t)
                                .get("ContinuousBackupsDescription", {})
                                .get("PointInTimeRecoveryDescription", {})
                                .get("PointInTimeRecoveryStatus") == "ENABLED")
                except Exception:
                    pass
                sse = bool(desc.get("SSEDescription") or {})
                public = False
                pol = desc.get("Policy")
                if pol and '"*"' in pol:
                    public = True
                snapshot["dynamodb"].append({"name": t, "pitr": pitr, "sse": sse, "public": public})
        except Exception as e:
            note("dynamodb", e, f"list_tables @{region}")
    for region in regions:
        try:
            rs = session.client("redshift", region_name=region)
            for c in rs.describe_clusters()["Clusters"]:
                logging = False
                try:
                    logging = bool(rs.describe_logging_status(ClusterIdentifier=c["ClusterIdentifier"])
                                   .get("LoggingEnabled"))
                except Exception:
                    pass
                snapshot["redshift"].append({
                    "id": c["ClusterIdentifier"],
                    "public": bool(c.get("PubliclyAccessible")),
                    "encrypted": bool(c.get("Encrypted")),
                    "logging": logging})
        except Exception as e:
            note("redshift", e, f"describe_clusters @{region}")
    for region in regions:
        try:
            efs = session.client("efs", region_name=region)
            for fs in efs.describe_file_systems()["FileSystems"]:
                backup = False
                try:
                    pol = efs.describe_backup_policy(FileSystemId=fs["FileSystemId"])
                    backup = pol.get("BackupPolicy", {}).get("Status") == "ENABLED"
                except Exception:
                    pass
                snapshot["efs"].append({"id": fs["FileSystemId"],
                                         "encrypted": bool(fs.get("Encrypted")), "backup": backup})
        except Exception as e:
            note("efs", e, f"describe_file_systems @{region}")
    for region in regions:
        try:
            ec_client = session.client("elasticache", region_name=region)
            for cc in ec_client.describe_cache_clusters()["CacheClusters"]:
                snapshot["elasticache"].append({
                    "id": cc["CacheClusterId"], "engine": cc.get("Engine"),
                    "at_rest": bool(cc.get("AtRestEncryptionEnabled")),
                    "transit": bool(cc.get("TransitEncryptionEnabled"))})
        except Exception as e:
            note("elasticache", e, f"describe_cache_clusters @{region}")

    # ---- ELB / EKS / API Gateway / Route53 / CloudWatch alarms ---------------------------
    for region in regions:
        try:
            elb = session.client("elbv2", region_name=region)
            for lb in elb.describe_load_balancers()["LoadBalancers"]:
                https = False
                access_logs = False
                try:
                    attrs = {a["Key"]: a["Value"] for a in
                             elb.describe_load_balancer_attributes(LoadBalancerArn=lb["LoadBalancerArn"])["Attributes"]}
                    access_logs = attrs.get("access_logs.s3.enabled") == "true"
                except Exception:
                    pass
                try:
                    for li in elb.describe_listeners(LoadBalancerArn=lb["LoadBalancerArn"])["Listeners"]:
                        if li.get("Protocol") in ("HTTPS", "TLS"):
                            https = True
                except Exception:
                    pass
                snapshot["elb"].append({"name": lb["LoadBalancerName"],
                                         "type": lb.get("Type"), "https": https,
                                         "access_logs": access_logs})
        except Exception as e:
            note("elbv2", e, f"load_balancers @{region}")
    for region in regions:
        try:
            eks = session.client("eks", region_name=region)
            for cl in eks.list_clusters()["clusters"]:
                desc = eks.describe_cluster(name=cl)["cluster"]
                ep = desc.get("resourcesVpcConfig", {})
                snapshot["eks"].append({"name": cl,
                                         "public_endpoint": bool(ep.get("endpointPublicAccess"))})
        except Exception as e:
            note("eks", e, f"list_clusters @{region}")
    for region in regions:
        try:
            ag = session.client("apigateway", region_name=region)
            for api in ag.get_rest_apis()["items"]:
                public = True  # REST APIs are public unless private endpoints configured
                logging = False
                try:
                    stages = ag.get_stages(restApiId=api["id"])["item"]
                    logging = any(s.get("methodSettings") for s in stages)
                except Exception:
                    pass
                snapshot["apigw"].append({"name": api["name"], "public": public,
                                           "logging": logging})
        except Exception as e:
            note("apigateway", e, f"get_rest_apis @{region}")
    try:
        r53 = session.client("route53", region_name=regions[0])
        zones = r53.list_hosted_zones()["HostedZones"]
        dnssec = False
        for z in zones:
            try:
                dnssec = bool(r53.get_dnssec(HostedZoneId=z["Id"]).get("Status", {}).get("ServeSigning"))
                if dnssec:
                    break
            except Exception:
                continue
        snapshot["r53"]["dnssec"] = dnssec
        snapshot["r53"]["zone_count"] = len(zones)
        try:
            ql = r53.list_query_logging_configs().get("QueryLoggingConfigs", [])
            snapshot["r53"]["query_logging"] = bool(ql)
        except Exception:
            snapshot["r53"]["query_logging"] = False
    except Exception as e:
        note("route53", e, "hosted zones")
    try:
        cw = session.client("cloudwatch", region_name=regions[0])
        paginator = cw.get_paginator("describe_alarms")
        names = []
        for page in paginator.paginate(AlarmTypes=["MetricAlarm"]):
            for a in page.get("MetricAlarms", []):
                names.append(a["AlarmName"])
        snapshot["cw"]["metric_alarms"] = names
    except Exception as e:
        note("cloudwatch", e, "describe_alarms")
    try:
        cw = session.client("cloudwatch", region_name=regions[0])
        snapshot["cw"]["dashboards"] = len(cw.list_dashboards().get("DashboardEntries", []))
    except Exception as e:
        note("cloudwatch", e, "list_dashboards")

    # ---- S3 account-level block public access -------------------------------------------
    try:
        s3 = session.client("s3", region_name=regions[0])
        try:
            pab = s3.get_account_public_access_block()["PublicAccessBlockConfiguration"]
            snapshot["s3_block_public"] = bool(pab.get("BlockPublicAcls") and pab.get("BlockPublicPolicy"))
        except Exception:
            snapshot["s3_block_public"] = False
        for b in snapshot["s3"]:
            try:
                cfg = s3.get_bucket_lifecycle_configuration(Bucket=b["name"])
                b["lifecycle"] = bool(cfg.get("Rules"))
            except Exception:
                b["lifecycle"] = False
    except Exception as e:
        note("s3", e, "get_account_public_access_block / lifecycle")

    # ---- CloudFront --------------------------------------------------------------------------
    try:
        cf = session.client("cloudfront", region_name=regions[0])
        for dist in cf.list_distributions().get("DistributionList", {}).get("Items", []):
            waf = bool(dist.get("WebACLId") and dist.get("WebACLId") != "")
            min_tls = ""
            default_cert = dist.get("ViewerCertificate", {}).get("CloudFrontDefaultCertificate", False)
            logging = bool(dist.get("Logging", {}).get("Enabled"))
            origin_http = False
            geo = ""
            fle = False
            oac = False
            try:
                desc = cf.get_distribution(Id=dist["Id"])["Distribution"]
                vc = desc["DistributionConfig"].get("ViewerCertificate", {})
                min_tls = vc.get("MinimumProtocolVersion", "")
                geo = (desc["DistributionConfig"].get("GeoRestriction") or {}).get("RestrictionType", "")
                fle = bool(desc["DistributionConfig"].get("FieldLevelEncryptionId"))
                for o in desc["DistributionConfig"].get("Origins", {}).get("Items", []):
                    if o.get("OriginProtocolPolicy") == "http-only":
                        origin_http = True
                    if (o.get("OriginAccessControlId")
                            or (o.get("S3OriginConfig") or {}).get("OriginAccessIdentity")):
                        oac = True
            except Exception:
                pass
            snapshot["cloudfront"].append({
                "id": dist["Id"], "waf_attached": waf, "min_tls": min_tls,
                "logging": logging, "default_cert": default_cert, "origin_http": origin_http,
                "geo_restricted": geo == "whitelist",
                "field_level_encryption": fle, "oac_oai": oac})
    except Exception as e:
        note("cloudfront", e, "list_distributions")

    # ---- ELB hardening extras (SSL policy / HTTP redirect / WAF) ------------------------------
    for region in regions:
        try:
            elb = session.client("elbv2", region_name=region)
            for lb in elb.describe_load_balancers()["LoadBalancers"]:
                entry = next((x for x in snapshot["elb"]
                              if x["name"] == lb["LoadBalancerName"]), None)
                if entry is None:
                    continue
                insecure_ssl = False
                http_no_redirect = False
                try:
                    for li in elb.describe_listeners(LoadBalancerArn=lb["LoadBalancerArn"])["Listeners"]:
                        sp = (li.get("SslPolicy") or "")
                        if sp and ("ELBSecurityPolicy-TLS-1-0" in sp or "ELBSecurityPolicy-TLS-1-1" in sp
                                   or "ELBSecurityPolicy-2016" in sp or "ELBSecurityPolicy-2015" in sp):
                            insecure_ssl = True
                        if li.get("Protocol") == "HTTP":
                            for act in li.get("DefaultActions", []):
                                redir = act.get("RedirectConfig")
                                if not (redir and redir.get("Protocol") == "HTTPS"):
                                    http_no_redirect = True
                except Exception:
                    pass
                entry["ssl_policy_secure"] = not insecure_ssl
                entry["http_no_redirect"] = http_no_redirect
        except Exception as e:
            note("elbv2", e, f"listener hardening @{region}")
    # ---- Classic ELB (elb API, separate from elbv2) -----------------------------------
    try:
        elb_cl = session.client("elb", region_name=regions[0])
        snapshot["elb_classic"] = []
        for lb in elb_cl.describe_load_balancers().get("LoadBalancerDescriptions", []):
            https = any((ld.get("Listener") or {}).get("Protocol") in ("HTTPS", "SSL")
                        for ld in lb.get("ListenerDescriptions", []))
            snapshot["elb_classic"].append({"name": lb["LoadBalancerName"], "https": https})
    except Exception as e:
        note("elb", e, "classic load balancers")
    # ---- RDS public snapshots ------------------------------------------------------------
    for region in regions:
        try:
            rds = session.client("rds", region_name=region)
            for s_ in rds.describe_db_snapshots().get("DBSnapshots", []):
                if s_.get("PubliclyAccessible"):
                    snapshot["rds_public_snapshots"] = True
        except Exception as e:
            note("rds", e, f"describe_db_snapshots @{region}")
    try:
        waf_regional = session.client("waf-regional", region_name=regions[0])
        associated = set()
        for r in waf_regional.list_web_acls()["WebACLs"]:
            try:
                for res in waf_regional.list_resources_for_web_acl(WebACLId=r["WebACLId"]).get("ResourceArns", []):
                    # ELB ARN: arn:...:loadbalancer/app/<name>/<hash> (or
                    # loadbalancer/<name>/<hash> for classic) -> name is [-2].
                    parts = res.split("/")
                    if len(parts) >= 2:
                        associated.add(parts[-2])
            except Exception:
                continue
        for lb in snapshot["elb"]:
            lb["waf_attached"] = lb["name"] in associated
    except Exception as e:
        note("waf-regional", e, "list_web_acls")

    # ---- EKS logging ------------------------------------------------------------------------------
    for region in regions:
        try:
            eks = session.client("eks", region_name=region)
            for cl in eks.list_clusters()["clusters"]:
                try:
                    desc = eks.describe_cluster(name=cl)["cluster"]
                    logging = desc.get("logging", {}).get("clusterLogging", [])
                    enabled = any(g.get("enabled") for g in logging if g.get("types"))
                    entry = next((x for x in snapshot["eks"] if x["name"] == cl), None)
                    if entry is not None:
                        entry["logging_enabled"] = bool(enabled)
                except Exception:
                    continue
        except Exception as e:
            note("eks", e, f"logging @{region}")

    # ---- CloudWatch log groups ---------------------------------------------------------------------
    for region in regions:
        try:
            logs = session.client("logs", region_name=region)
            for lg in logs.describe_log_groups()["logGroups"]:
                snapshot["loggroups"].append({
                    "name": lg["logGroupName"],
                    "retention_days": lg.get("retentionInDays"),
                    "encrypted": bool(lg.get("kmsKeyId")),
                })
        except Exception as e:
            note("logs", e, f"log groups @{region}")

    # ---- AWS Backup plans ---------------------------------------------------------------------------
    try:
        backup = session.client("backup", region_name=regions[0])
        snapshot["backup"]["plans"] = len(backup.list_backup_plans().get("BackupPlansList", []))
        snapshot["backup"]["vaults"] = len(backup.list_backup_vaults().get("BackupVaultList", []))
    except Exception as e:
        note("backup", e, "list_backup_plans / vaults")

    # ---- Secrets Manager KMS ---------------------------------------------------------------------------
    for region in regions:
        try:
            sm = session.client("secretsmanager", region_name=region)
            for s in sm.list_secrets()["SecretList"]:
                entry = next((x for x in snapshot["secrets"] if x["name"] == s["Name"]), None)
                if entry is not None:
                    entry["kms_cmk"] = bool(s.get("KmsKeyId"))
        except Exception as e:
            note("secretsmanager", e, f"kms @{region}")

    # ---- EBS snapshots -----------------------------------------------------------------------------------
    for region in regions:
        try:
            ec2 = session.client("ec2", region_name=region)
            for snap in ec2.describe_snapshots(OwnerIds=[account_id])["Snapshots"]:
                snapshot["snapshots"].append({"id": snap["SnapshotId"],
                                               "public": bool(snap.get("Public")),
                                               "encrypted": bool(snap.get("Encrypted"))})
        except Exception as e:
            note("ec2", e, f"describe_snapshots @{region}")

    # ---- ECS (clusters + task definitions) ----------------------------------------------------------
    try:
        ecs = session.client("ecs", region_name=regions[0])
        for arn in ecs.list_clusters().get("clusterArns", []):
            insights = False
            try:
                detail = ecs.describe_clusters(clusters=[arn])["clusters"][0]
                insights = any(
                    s.get("name") == "containerInsights" and s.get("value") == "enabled"
                    for s in detail.get("settings", []))
            except Exception:
                pass
            snapshot["ecs"]["clusters"].append({"name": arn.rsplit("/", 1)[-1],
                                                 "container_insights": insights})
        for arn in ecs.list_task_definitions().get("taskDefinitionArns", [])[:20]:
            try:
                td = ecs.describe_task_definition(taskDefinition=arn)["taskDefinition"]
                snapshot["ecs"]["task_definitions"].append({
                    "name": td.get("family", arn.rsplit("/", 1)[-1]),
                    "network_mode": td.get("networkMode", ""),
                    "execution_role": bool(td.get("executionRoleArn")),
                })
            except Exception:
                continue
    except Exception as e:
        note("ecs", e, "clusters / task definitions")

    # ---- IoT / SES --------------------------------------------------------------------------------------
    try:
        iot = session.client("iot", region_name=regions[0])
        log_level = ""
        try:
            log_level = iot.get_logging_options().get("loggingLevel", "")
        except Exception:
            pass
        public_policies = []
        for p in iot.list_policies().get("policies", []):
            try:
                doc = iot.get_policy(policyName=p["policyName"])["policyDocument"]
                if '"*"' in doc:
                    public_policies.append(p["policyName"])
            except Exception:
                continue
        snapshot["iot"] = {"logging_level": log_level, "public_policies": public_policies}
    except Exception as e:
        note("iot", e, "policies / logging")
    try:
        ses = session.client("ses", region_name=regions[0])
        ids = ses.list_identities().get("Identities", [])
        dkim = ses.get_identity_dkim_attributes(Identities=ids).get("DkimAttributes", {})
        unverified = [i for i in ids
                      if dkim.get(i, {}).get("DkimVerificationStatus") != "Success"]
        snapshot["ses"] = {"identities": ids, "dkim_unverified": unverified}
    except Exception as e:
        note("ses", e, "identities / dkim")

    # ---- ELB deletion protection / EFS lifecycle / S3 object lock / DDB protection ----------------------
    for region in regions:
        try:
            elb = session.client("elbv2", region_name=region)
            for lb in elb.describe_load_balancers()["LoadBalancers"]:
                entry = next((x for x in snapshot["elb"]
                              if x["name"] == lb["LoadBalancerName"]), None)
                if entry is None:
                    continue
                try:
                    attrs = {a["Key"]: a["Value"] for a in
                             elb.describe_load_balancer_attributes(
                                 LoadBalancerArn=lb["LoadBalancerArn"])["Attributes"]}
                    entry["deletion_protection"] = attrs.get("deletion_protection.enabled") == "true"
                except Exception:
                    entry["deletion_protection"] = False
        except Exception as e:
            note("elbv2", e, f"deletion protection @{region}")
    for region in regions:
        try:
            efs = session.client("efs", region_name=region)
            for fs in efs.describe_file_systems()["FileSystems"]:
                entry = next((x for x in snapshot["efs"] if x["id"] == fs["FileSystemId"]), None)
                if entry is None:
                    continue
                try:
                    lc = efs.describe_lifecycle_configuration(FileSystemId=fs["FileSystemId"])
                    entry["lifecycle_policy"] = bool(lc.get("LifecyclePolicies"))
                except Exception:
                    entry["lifecycle_policy"] = False
        except Exception as e:
            note("efs", e, f"lifecycle @{region}")
    try:
        s3 = session.client("s3", region_name=regions[0])
        for b in snapshot["s3"]:
            try:
                s3.get_object_lock_configuration(Bucket=b["name"])
                b["object_lock"] = True
            except Exception:
                b["object_lock"] = False
    except Exception as e:
        note("s3", e, "object lock")
    for region in regions:
        try:
            ddb = session.client("dynamodb", region_name=region)
            for t in ddb.list_tables()["TableNames"]:
                try:
                    desc = ddb.describe_table(TableName=t)["Table"]
                    entry = next((x for x in snapshot["dynamodb"] if x["name"] == t), None)
                    if entry is not None:
                        entry["deletion_protection"] = bool(desc.get("DeletionProtectionEnabled"))
                except Exception:
                    continue
        except Exception as e:
            note("dynamodb", e, f"deletion protection @{region}")
    for region in regions:
        try:
            gd = session.client("guardduty", region_name=region)
            for d in gd.list_detectors()["DetectorIds"]:
                entry = next((x for x in snapshot["guardduty"] if x["id"] == d), None)
                if entry is None:
                    continue
                try:
                    det = gd.get_detector(DetectorId=d)
                    feats = det.get("Features")
                    if feats is None:
                        entry["s3_protection"] = None
                    else:
                        entry["s3_protection"] = any(
                            f.get("Name") == "S3_DATA_EVENTS" and f.get("Status") == "ENABLED"
                            for f in feats)
                except Exception:
                    entry["s3_protection"] = None
        except Exception as e:
            note("guardduty", e, f"s3 protection @{region}")
    for region in regions:
        try:
            rds = session.client("rds", region_name=region)
            for db in rds.describe_db_instances()["DBInstances"]:
                entry = next((x for x in snapshot["rds"]
                              if x["id"] == db["DBInstanceIdentifier"]), None)
                if entry is not None:
                    entry["enhanced_monitoring"] = int(db.get("MonitoringInterval", 0)) > 0
        except Exception as e:
            note("rds", e, f"enhanced monitoring @{region}")

    # ---- SageMaker (ML): notebook internet access, KMS, endpoint data capture ---
    for region in regions:
        try:
            sm = session.client("sagemaker", region_name=region)
            notebooks = []
            try:
                for nb in sm.list_notebook_instances().get("NotebookInstances", []):
                    detail = sm.describe_notebook_instance(
                        NotebookInstanceName=nb["NotebookInstanceName"])
                    notebooks.append({
                        "name": nb["NotebookInstanceName"],
                        "direct_internet": bool(detail.get("DirectInternetAccess")
                                                == "Enabled"),
                        "kms_key": detail.get("KmsKeyId"),
                    })
            except Exception as e:
                note("sagemaker", e, f"notebook instances @{region}")
            endpoints = []
            try:
                for ep in sm.list_endpoints().get("Endpoints", []):
                    endpoints.append({
                        "name": ep["EndpointName"],
                        "data_capture": bool(
                            ep.get("DataCaptureConfig") or
                            sm.describe_endpoint_config(
                                EndpointConfigName=ep.get("EndpointConfigName") or "")
                            .get("DataCaptureConfig")),
                    })
            except Exception as e:
                note("sagemaker", e, f"endpoints @{region}")
            if notebooks or endpoints:
                snapshot.setdefault("sagemaker", {"notebooks": [], "endpoints": []})
                snapshot["sagemaker"]["notebooks"].extend(notebooks)
                snapshot["sagemaker"]["endpoints"].extend(endpoints)
        except Exception as e:
            note("sagemaker", e, f"client @{region}")

    return snapshot, errors
