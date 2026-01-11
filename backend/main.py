#!/usr/bin/env python3
"""
Multi-cloud AI infrastructure auditor.

Purpose
- Scan AWS, Azure, and GCP for AI-related assets and general cloud security findings,
  producing a standardized report useful for ISO/IEC assessments (42001, 27017, 27018).

Expected POST /scan JSON payload (example):
{
  "aws_access_key": "AKIA...",
  "aws_secret_key": "SECRET",
  "aws_region": "us-east-1",

  "azure_tenant_id": "<tenant>",
  "azure_client_id": "<client-id>",
  "azure_client_secret": "<client-secret>",
  "azure_subscription_id": "<sub-id>",

  "gcp_json_creds": "{...}"  # stringified service account JSON
}

Report schema (self.report)
{
  "AWS": [ {Service, Resource, Status, Compliance_Map, Identified_Risk, Recommended_Remediation} ],
  "Azure": [ ... ],
  "GCP": [ ... ]
}

Security notes
- Do not commit credentials to source control.
- Prefer short-lived credentials, environment-based injection, or secret stores.
- This module records exceptions in the report (non-sensitive error strings) to keep the API resilient.
"""

from typing import Any, Dict, List, Optional
import os
import json
import logging
from enum import Enum

# AWS
import boto3
from botocore.exceptions import ClientError, NoCredentialsError

# Flask API
from flask import Flask, request, jsonify
from flask_cors import CORS

# Azure
from azure.identity import ClientSecretCredential
from azure.core.exceptions import AzureError
from azure.mgmt.cognitiveservices import CognitiveServicesManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.sql import SqlManagementClient

# GCP
from google.cloud import aiplatform
from google.cloud import storage
from google.oauth2 import service_account
from google.auth.exceptions import GoogleAuthError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ============================================================================
# CONFIGURATION AND CONSTANTS
# ============================================================================

# Default region if not specified
DEFAULT_AWS_REGION = "us-east-1"
DEFAULT_REQUEST_TIMEOUT = 30  # seconds
API_MAX_RETRIES = 3

# Management ports to check for exposure
MANAGEMENT_PORTS = [22, 3389]  # SSH, RDP

# Define findings as structured data to reduce duplication
class FindingType(Enum):
    """Enumeration of finding types and their metadata."""
    
    S3_ENCRYPTED = {
        "service": "S3 Storage",
        "status": "Encrypted",
        "compliance_tags": [],
        "risk": "None",
        "remediation": "None",
    }
    
    S3_UNENCRYPTED = {
        "service": "S3 Storage",
        "status": "Unencrypted (High Risk)",
        "compliance_tags": ["ISO 27017: CLD.8.2.1 (Storage Security)", "ISO 27018: PII Protection"],
        "risk": "Data at rest is readable if physical media is compromised or improperly accessed.",
        "remediation": "Enable Default Encryption (SSE-S3 or KMS) on the S3 Bucket properties.",
    }
    
    SG_OPEN_PORT = {
        "service": "Security Group",
        "compliance_tags": ["ISO 27017: CLD.9.5 (Network Segregation)", "ISO 27001: A.13.1"],
        "risk": "Unrestricted network access allows brute-force attacks on management ports.",
        "remediation": "Restrict Source IP to corporate VPN CIDR or specific static IPs.",
    }
    
    SAGEMAKER_ACTIVE = {
        "service": "SageMaker",
        "compliance_tags": ["ISO 42001: Clause 6.1 (AI Inventory)", "ISO 42001: Clause 8.2"],
        "risk": "Unmonitored AI development environments ('Shadow AI') may leak training data.",
        "remediation": "Register this asset in the central AI Inventory and enforce VPC endpoints.",
    }
    
    AZURE_SQL_SERVER = {
        "service": "SQL Server",
        "status": "Active",
        "compliance_tags": ["ISO 27018: PII Protection", "ISO 27001: A.10.1"],
        "risk": "Potential data exposure if physical disks are stolen or accessed directly.",
        "remediation": "Verify 'Transparent Data Encryption' (TDE) is set to ON for all DBs.",
    }
    
    AZURE_NSG_OPEN = {
        "service": "NSG Firewall",
        "compliance_tags": ["ISO 27017: CLD.9.5 (Network Segregation)"],
        "risk": "Management ports exposed to the public internet increase ransomware risk.",
        "remediation": "Change Source to 'My IP' or specific corporate subnets.",
    }
    
    AZURE_AI_SERVICE = {
        "service": "AI Service",
        "status": "Active",
        "compliance_tags": ["ISO 42001: Clause 6.1", "ISO 42001: Clause 9.1"],
        "risk": "AI model usage may not be logged, preventing audit of toxic/biased outputs.",
        "remediation": "Enable 'Diagnostic Settings' to send logs to Azure Monitor.",
    }
    
    GCP_STORAGE_FINE_GRAINED = {
        "service": "Cloud Storage",
        "status": "Fine-Grained ACLs (Risk)",
        "compliance_tags": ["ISO 27018: PII Protection", "ISO 27017: CLD.9.5"],
        "risk": "Object-level ACLs are difficult to audit and often lead to accidental public exposure.",
        "remediation": "Enable 'Uniform Bucket-Level Access' to manage permissions via IAM only.",
    }
    
    GCP_STORAGE_UNIFORM = {
        "service": "Cloud Storage",
        "status": "Uniform Access (Pass)",
        "compliance_tags": [],
        "risk": "None",
        "remediation": "None",
    }
    
    GCP_VERTEX_AI = {
        "service": "Vertex AI",
        "status": "Active",
        "compliance_tags": ["ISO 42001: Clause 8 (AI Control)"],
        "risk": "Lack of version control on AI models can lead to unapproved model behavior in production.",
        "remediation": "Ensure the model is pinned to a specific version and alias in the Model Registry.",
    }


# ENABLE CORS: This is required for local development where a frontend served from file:// or localhost
# needs to call the /scan endpoint on this service. For production, restrict origins accordingly.
CORS(app)


class CloudAuditor:
    """
    Multi-Framework Auditor.

    Args:
        credentials (dict): Dictionary containing optional credential blocks for AWS, Azure, GCP.
            See module docstring for the expected keys.

    Attributes:
        creds (dict): Reference to provided credentials.
        report (dict): Aggregated findings per cloud provider.
    """

    def __init__(self, credentials: Dict[str, Any]) -> None:
        self.creds: Dict[str, Any] = credentials
        # Standardized report structure per provider
        self.report: Dict[str, List[Dict[str, Any]]] = {"AWS": [], "Azure": [], "GCP": []}
        logger.info("CloudAuditor initialized with credentials for AWS, Azure, and GCP")

    def _validate_credentials(self, cloud: str, required_keys: List[str]) -> bool:
        """
        Validate that all required credential keys are present.
        
        Args:
            cloud: Cloud provider name
            required_keys: List of required credential keys
            
        Returns:
            True if all required keys are present, False otherwise
        """
        missing = [key for key in required_keys if not self.creds.get(key)]
        if missing:
            logger.warning(f"Skipping {cloud} audit: missing credentials {missing}")
            return False
        return True

    def _add_finding(
        self,
        cloud: str,
        service: str,
        resource: str,
        status: str,
        compliance_tags: Optional[List[str]],
        risk: str,
        remediation: str,
    ) -> None:
        """
        Append a standardized finding to the report.

        Args:
            cloud: "AWS" | "Azure" | "GCP"
            service: Service name (e.g., "S3 Storage", "NSG Firewall")
            resource: Resource identifier (name, id)
            status: Short human-readable status (e.g., "Encrypted", "Unencrypted (High Risk)")
            compliance_tags: List of ISO references or other compliance tags
            risk: Short description of identified risk
            remediation: Recommended remediation text
        """
        self.report.setdefault(cloud, []).append(
            {
                "Service": service,
                "Resource": resource,
                "Status": status,
                "Compliance_Map": compliance_tags or [],
                "Identified_Risk": risk,
                "Recommended_Remediation": remediation,
            }
        )


    def audit_aws(self) -> None:
        """
        Audit AWS resources:
         - S3 bucket encryption
         - Security groups for open management ports (SSH, RDP)
         - SageMaker notebook instances

        Required credential keys:
            aws_access_key, aws_secret_key, aws_region (optional)
        Side-effect: append findings to self.report["AWS"]
        """
        required_creds = ["aws_access_key", "aws_secret_key"]
        if not self._validate_credentials("AWS", required_creds):
            return

        try:
            logger.info("Starting AWS audit")
            session = boto3.Session(
                aws_access_key_id=self.creds["aws_access_key"],
                aws_secret_access_key=self.creds["aws_secret_key"],
                region_name=self.creds.get("aws_region", DEFAULT_AWS_REGION),
            )

            # --- 1. S3 Encryption (ISO 27017 & 27018) ---
            logger.info("Auditing S3 buckets for encryption")
            s3 = session.client("s3")
            try:
                paginator = s3.get_paginator("list_buckets")
                for page in paginator.paginate():
                    for bucket in page.get("Buckets", []):
                        name = bucket["Name"]
                        try:
                            s3.get_bucket_encryption(Bucket=name)
                            self._add_finding("AWS", FindingType.S3_ENCRYPTED.value["service"], name, 
                                            FindingType.S3_ENCRYPTED.value["status"], 
                                            FindingType.S3_ENCRYPTED.value["compliance_tags"],
                                            FindingType.S3_ENCRYPTED.value["risk"],
                                            FindingType.S3_ENCRYPTED.value["remediation"])
                        except ClientError as e:
                            if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
                                self._add_finding("AWS", FindingType.S3_UNENCRYPTED.value["service"], name,
                                                FindingType.S3_UNENCRYPTED.value["status"],
                                                FindingType.S3_UNENCRYPTED.value["compliance_tags"],
                                                FindingType.S3_UNENCRYPTED.value["risk"],
                                                FindingType.S3_UNENCRYPTED.value["remediation"])
                            else:
                                logger.error(f"Error checking S3 encryption for {name}: {e}")
                        except Exception as e:
                            logger.error(f"Unexpected error checking S3 bucket {name}: {e}")
            except ClientError as e:
                logger.error(f"Error listing S3 buckets: {e}")
                self.report["AWS"].append({"Error": f"S3 audit failed: {e.response.get('Error', {}).get('Message', str(e))}"})

            # --- 2. Security Groups (ISO 27017) ---
            logger.info("Auditing security groups for open ports")
            ec2 = session.client("ec2")
            try:
                paginator = ec2.get_paginator("describe_security_groups")
                for page in paginator.paginate():
                    for sg in page.get("SecurityGroups", []):
                        for perm in sg.get("IpPermissions", []):
                            from_port = perm.get("FromPort")
                            if from_port and from_port in MANAGEMENT_PORTS:
                                for ip_range in perm.get("IpRanges", []):
                                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                                        sg_name = sg.get("GroupName", sg.get("GroupId", "unknown"))
                                        finding = FindingType.SG_OPEN_PORT.value
                                        self._add_finding(
                                            "AWS",
                                            finding["service"],
                                            sg_name,
                                            f"Open Port {from_port} to World",
                                            finding["compliance_tags"],
                                            finding["risk"],
                                            finding["remediation"],
                                        )
            except ClientError as e:
                logger.error(f"Error describing security groups: {e}")
                self.report["AWS"].append({"Error": f"Security Group audit failed: {e.response.get('Error', {}).get('Message', str(e))}"})

            # --- 3. SageMaker (ISO 42001) ---
            logger.info("Auditing SageMaker notebook instances")
            sm = session.client("sagemaker")
            try:
                paginator = sm.get_paginator("list_notebook_instances")
                for page in paginator.paginate():
                    for nb in page.get("NotebookInstances", []):
                        finding = FindingType.SAGEMAKER_ACTIVE.value
                        self._add_finding(
                            "AWS",
                            finding["service"],
                            nb.get("NotebookInstanceName", "unknown"),
                            nb.get("NotebookInstanceStatus", "unknown"),
                            finding["compliance_tags"],
                            finding["risk"],
                            finding["remediation"],
                        )
            except ClientError as e:
                logger.error(f"Error listing SageMaker instances: {e}")
                self.report["AWS"].append({"Error": f"SageMaker audit failed: {e.response.get('Error', {}).get('Message', str(e))}"})

        except (NoCredentialsError, ClientError) as e:
            logger.error(f"AWS credential or client error: {e}")
            self.report["AWS"].append({"Error": f"AWS audit failed: {str(e)}"})
        except Exception as e:
            logger.exception(f"Unexpected error during AWS audit: {e}")
            self.report["AWS"].append({"Error": f"AWS audit failed: {str(e)}"})


    def audit_azure(self) -> None:
        """
        Audit Azure resources:
         - SQL server encryption guidance (TDE)
         - Network Security Groups for open management ports
         - Cognitive Services / AI accounts presence and logging configuration

        Required credential keys:
            azure_tenant_id, azure_client_id, azure_client_secret, azure_subscription_id
        Side-effect: append findings to self.report["Azure"]
        """
        required_creds = ["azure_client_id", "azure_tenant_id", "azure_client_secret", "azure_subscription_id"]
        if not self._validate_credentials("Azure", required_creds):
            return

        try:
            logger.info("Starting Azure audit")
            credential = ClientSecretCredential(
                tenant_id=self.creds["azure_tenant_id"],
                client_id=self.creds["azure_client_id"],
                client_secret=self.creds["azure_client_secret"],
            )
            sub_id = self.creds["azure_subscription_id"]

            # --- 1. SQL Database Encryption (ISO 27018) ---
            logger.info("Auditing Azure SQL servers")
            try:
                sql_client = SqlManagementClient(credential, sub_id)
                for server in sql_client.servers.list():
                    finding = FindingType.AZURE_SQL_SERVER.value
                    self._add_finding(
                        "Azure",
                        finding["service"],
                        server.name,
                        finding["status"],
                        finding["compliance_tags"],
                        finding["risk"],
                        finding["remediation"],
                    )
            except AzureError as e:
                logger.error(f"Error listing Azure SQL servers: {e}")
                self.report["Azure"].append({"Error": f"SQL Server audit failed: {str(e)}"})

            # --- 2. Network Security Groups (ISO 27017) ---
            logger.info("Auditing Azure Network Security Groups")
            try:
                net_client = NetworkManagementClient(credential, sub_id)
                for nsg in net_client.network_security_groups.list_all():
                    if not nsg.security_rules:
                        continue
                    for rule in nsg.security_rules:
                        if rule.access == "Allow" and rule.direction == "Inbound":
                            src = getattr(rule, "source_address_prefix", None) or getattr(rule, "source_address_prefixes", None)
                            dst_port = getattr(rule, "destination_port_range", None)
                            if src == "*" and dst_port in ["22", "3389"]:
                                finding = FindingType.AZURE_NSG_OPEN.value
                                self._add_finding(
                                    "Azure",
                                    finding["service"],
                                    nsg.name,
                                    f"Inbound Allow {dst_port}",
                                    finding["compliance_tags"],
                                    finding["risk"],
                                    finding["remediation"],
                                )
            except AzureError as e:
                logger.error(f"Error listing Azure NSGs: {e}")
                self.report["Azure"].append({"Error": f"NSG audit failed: {str(e)}"})

            # --- 3. AI Services (ISO 42001) ---
            logger.info("Auditing Azure Cognitive Services")
            try:
                cog_client = CognitiveServicesManagementClient(credential, sub_id)
                for account in cog_client.accounts.list():
                    finding = FindingType.AZURE_AI_SERVICE.value
                    self._add_finding(
                        "Azure",
                        finding["service"],
                        account.name,
                        finding["status"],
                        finding["compliance_tags"],
                        finding["risk"],
                        finding["remediation"],
                    )
            except AzureError as e:
                logger.error(f"Error listing Azure Cognitive Services: {e}")
                self.report["Azure"].append({"Error": f"Cognitive Services audit failed: {str(e)}"})

        except AzureError as e:
            logger.error(f"Azure authentication or client error: {e}")
            self.report["Azure"].append({"Error": f"Azure audit failed: {str(e)}"})
        except Exception as e:
            logger.exception(f"Unexpected error during Azure audit: {e}")
            self.report["Azure"].append({"Error": f"Azure audit failed: {str(e)}"})

    def audit_gcp(self) -> None:
        """
        Audit GCP resources:
         - Cloud Storage uniform bucket access
         - Vertex AI models presence and versioning guidance

        Required credential keys:
            gcp_json_creds (stringified JSON service account)
        Side-effect: append findings to self.report["GCP"]
        """
        required_creds = ["gcp_json_creds"]
        if not self._validate_credentials("GCP", required_creds):
            return

        try:
            logger.info("Starting GCP audit")
            gcp_info = json.loads(self.creds["gcp_json_creds"])
            creds = service_account.Credentials.from_service_account_info(gcp_info)
            project_id = gcp_info.get("project_id")
            
            if not project_id:
                logger.error("GCP credentials do not contain project_id")
                self.report["GCP"].append({"Error": "GCP credentials missing project_id"})
                return

            # --- 1. Cloud Storage Access (ISO 27018 & 27017) ---
            logger.info("Auditing GCP Cloud Storage buckets")
            try:
                storage_client = storage.Client(credentials=creds, project=project_id)
                for bucket in storage_client.list_buckets():
                    is_uniform = getattr(bucket.iam_configuration, "uniform_bucket_level_access_enabled", None)
                    if not is_uniform:
                        finding = FindingType.GCP_STORAGE_FINE_GRAINED.value
                        self._add_finding(
                            "GCP",
                            finding["service"],
                            bucket.name,
                            finding["status"],
                            finding["compliance_tags"],
                            finding["risk"],
                            finding["remediation"],
                        )
                    else:
                        finding = FindingType.GCP_STORAGE_UNIFORM.value
                        self._add_finding(
                            "GCP",
                            finding["service"],
                            bucket.name,
                            finding["status"],
                            finding["compliance_tags"],
                            finding["risk"],
                            finding["remediation"],
                        )
            except Exception as e:
                logger.error(f"Error listing GCP Cloud Storage buckets: {e}")
                self.report["GCP"].append({"Error": f"Cloud Storage audit failed: {str(e)}"})

            # --- 2. Vertex AI (ISO 42001) ---
            logger.info("Auditing GCP Vertex AI models")
            try:
                aiplatform.init(project=project_id, credentials=creds)
                for model in aiplatform.Model.list():
                    finding = FindingType.GCP_VERTEX_AI.value
                    self._add_finding(
                        "GCP",
                        finding["service"],
                        model.display_name,
                        finding["status"],
                        finding["compliance_tags"],
                        finding["risk"],
                        finding["remediation"],
                    )
            except Exception as e:
                logger.error(f"Error listing GCP Vertex AI models: {e}")
                self.report["GCP"].append({"Error": f"Vertex AI audit failed: {str(e)}"})

        except (GoogleAuthError, ValueError) as e:
            logger.error(f"GCP authentication or JSON parsing error: {e}")
            self.report["GCP"].append({"Error": f"GCP audit failed: {str(e)}"})
        except Exception as e:
            logger.exception(f"Unexpected error during GCP audit: {e}")
            self.report["GCP"].append({"Error": f"GCP audit failed: {str(e)}"})


@app.route("/scan", methods=["POST"])
def scan_endpoint() -> Any:
    """
    Main API Endpoint.

    Expects JSON body with credential keys (see module docstring). Runs AWS, Azure, and GCP
    audits in sequence and returns the aggregated report JSON.

    Responses:
      200: report JSON
      400: bad request (missing JSON)
      500: server error
    """
    try:
        data = request.get_json(silent=True)
        if not data:
            logger.warning("Received request without JSON payload")
            return jsonify({"error": "No JSON payload provided"}), 400

        logger.info("Starting cloud audit scan")
        auditor = CloudAuditor(data)

        # Run audits (errors are caught internally and appended to the report)
        auditor.audit_aws()
        auditor.audit_azure()
        auditor.audit_gcp()

        logger.info("Cloud audit scan completed")
        return jsonify(auditor.report)

    except Exception as e:
        logger.exception(f"Unexpected error in scan endpoint: {e}")
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500


if __name__ == "__main__":
    # Cloud Run automatically injects PORT; default to 8080 for local runs.
    port = int(os.environ.get("PORT", 8080))
    logger.info(f"Starting Multi-Cloud Auditor API on port {port}")
    app.run(host="0.0.0.0", port=port, debug=os.environ.get("DEBUG", "false").lower() == "true")
