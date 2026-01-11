import os
import json
import boto3
from flask import Flask, request, jsonify
from flask_cors import CORS

# Azure Imports
from azure.identity import ClientSecretCredential
from azure.mgmt.cognitiveservices import CognitiveServicesManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.sql import SqlManagementClient

# GCP Imports
from google.cloud import aiplatform
from google.cloud import storage
from google.oauth2 import service_account

app = Flask(__name__)
CORS(app)

class CloudAuditor:
    """
    Multi-Framework Auditor.
    Checks assets against:
    - ISO/IEC 42001:2023 (AI Management System)
    - ISO/IEC 27017:2015 (Cloud Security)
    - ISO/IEC 27018:2019 (Cloud Privacy & PII)
    """
    def __init__(self, credentials):
        self.creds = credentials
        self.report = {"AWS": [], "Azure": [], "GCP": []}

    def _add_finding(self, cloud, service, resource, status, compliance_tags, risk, remediation):
        """
        Standardizes the report format with Risk and Remediation context.
        """
        self.report[cloud].append({
            "Service": service,
            "Resource": resource,
            "Status": status,
            "Compliance_Map": compliance_tags,
            "Identified_Risk": risk,
            "Recommended_Remediation": remediation
        })

    def audit_aws(self):
        if not self.creds.get('aws_access_key'): return
        try:
            session = boto3.Session(
                aws_access_key_id=self.creds['aws_access_key'],
                aws_secret_access_key=self.creds['aws_secret_key'],
                region_name=self.creds.get('aws_region', 'us-east-1')
            )

            # --- 1. S3 Encryption (ISO 27017 & 27018) ---
            s3 = session.client('s3')
            for bucket in s3.list_buckets().get('Buckets', []):
                name = bucket['Name']
                try:
                    s3.get_bucket_encryption(Bucket=name)
                    # Pass (Encrypted)
                    self._add_finding("AWS", "S3 Storage", name, "Encrypted", [], "None", "None")
                except:
                    # Fail (Unencrypted)
                    self._add_finding(
                        "AWS", "S3 Storage", name, "Unencrypted (High Risk)", 
                        ["ISO 27017: CLD.8.2.1 (Storage Security)", "ISO 27018: PII Protection"],
                        risk="Data at rest is readable if physical media is compromised or improperly accessed.",
                        remediation="Enable Default Encryption (SSE-S3 or KMS) on the S3 Bucket properties."
                    )

            # --- 2. Security Groups / Firewall (ISO 27017) ---
            ec2 = session.client('ec2')
            sgs = ec2.describe_security_groups()['SecurityGroups']
            for sg in sgs:
                for perm in sg['IpPermissions']:
                    # Check for 0.0.0.0/0 on sensitive ports (22 SSH, 3389 RDP)
                    if 'FromPort' in perm and perm['FromPort'] in [22, 3389]:
                        for ip_range in perm.get('IpRanges', []):
                            if ip_range.get('CidrIp') == '0.0.0.0/0':
                                self._add_finding(
                                    "AWS", "Security Group", sg['GroupName'], 
                                    f"Open Port {perm['FromPort']} to World", 
                                    ["ISO 27017: CLD.9.5 (Network Segregation)", "ISO 27001: A.13.1"],
                                    risk="Unrestricted network access allows brute-force attacks on management ports.",
                                    remediation="Restrict Source IP to corporate VPN CIDR or specific static IPs."
                                )

            # --- 3. SageMaker (ISO 42001) ---
            sm = session.client('sagemaker')
            for nb in sm.list_notebook_instances().get('NotebookInstances', []):
                self._add_finding(
                    "AWS", "SageMaker", nb['NotebookInstanceName'], nb['NotebookInstanceStatus'], 
                    ["ISO 42001: Clause 6.1 (AI Inventory)", "ISO 42001: Clause 8.2"],
                    risk="Unmonitored AI development environments ('Shadow AI') may leak training data.",
                    remediation="Register this asset in the central AI Inventory and enforce VPC endpoints."
                )

        except Exception as e:
            self.report['AWS'].append({"Error": str(e)})

    def audit_azure(self):
        if not self.creds.get('azure_client_id'): return
        try:
            credential = ClientSecretCredential(
                tenant_id=self.creds['azure_tenant_id'],
                client_id=self.creds['azure_client_id'],
                client_secret=self.creds['azure_client_secret']
            )
            sub_id = self.creds['azure_subscription_id']

            # --- 1. SQL Database Encryption (ISO 27018) ---
            sql_client = SqlManagementClient(credential, sub_id)
            servers = sql_client.servers.list()
            for server in servers:
                # In a full production script, we would iterate databases to check TDE status individually
                self._add_finding(
                    "Azure", "SQL Server", server.name, "Active", 
                    ["ISO 27018: PII Protection", "ISO 27001: A.10.1"],
                    risk="Potential data exposure if physical disks are stolen or accessed directly.",
                    remediation="Verify 'Transparent Data Encryption' (TDE) is set to ON for all DBs."
                )

            # --- 2. Network Security Groups (ISO 27017) ---
            net_client = NetworkManagementClient(credential, sub_id)
            for nsg in net_client.network_security_groups.list_all():
                for rule in nsg.security_rules:
                    if rule.access == 'Allow' and rule.direction == 'Inbound' and rule.source_address_prefix == '*':
                         if rule.destination_port_range in ['22', '3389']:
                             self._add_finding(
                                 "Azure", "NSG Firewall", nsg.name, 
                                 f"Inbound Allow {rule.destination_port_range}", 
                                 ["ISO 27017: CLD.9.5 (Network Segregation)"],
                                 risk="Management ports exposed to the public internet increase ransomware risk.",
                                 remediation="Change Source to 'My IP' or specific corporate subnets."
                             )

            # --- 3. AI Services (ISO 42001) ---
            cog_client = CognitiveServicesManagementClient(credential, sub_id)
            for account in cog_client.accounts.list():
                self._add_finding(
                    "Azure", "AI Service", account.name, "Active", 
                    ["ISO 42001: Clause 6.1", "ISO 42001: Clause 9.1"],
                    risk="AI model usage may not be logged, preventing audit of toxic/biased outputs.",
                    remediation="Enable 'Diagnostic Settings' to send logs to Azure Monitor."
                )

        except Exception as e:
            self.report['Azure'].append({"Error": str(e)})

    def audit_gcp(self):
        if not self.creds.get('gcp_json_creds'): return
        try:
            gcp_info = json.loads(self.creds['gcp_json_creds'])
            creds = service_account.Credentials.from_service_account_info(gcp_info)
            project_id = gcp_info['project_id']

            # --- 1. Cloud Storage Access (ISO 27018 & 27017) ---
            storage_client = storage.Client(credentials=creds, project=project_id)
            for bucket in storage_client.list_buckets():
                is_uniform = bucket.iam_configuration.uniform_bucket_level_access_enabled
                
                if not is_uniform:
                    self._add_finding(
                        "GCP", "Cloud Storage", bucket.name, "Fine-Grained ACLs (Risk)", 
                        ["ISO 27018: PII Protection", "ISO 27017: CLD.9.5"],
                        risk="Object-level ACLs are difficult to audit and often lead to accidental public exposure.",
                        remediation="Enable 'Uniform Bucket-Level Access' to manage permissions via IAM only."
                    )
                else:
                     self._add_finding("GCP", "Cloud Storage", bucket.name, "Uniform Access (Pass)", [], "None", "None")

            # --- 2. Vertex AI (ISO 42001) ---
            aiplatform.init(project=project_id, credentials=creds)
            for model in aiplatform.Model.list():
                self._add_finding(
                    "GCP", "Vertex AI", model.display_name, "Active", 
                    ["ISO 42001: Clause 8 (AI Control)"],
                    risk="Lack of version control on AI models can lead to unapproved model behavior in production.",
                    remediation="Ensure the model is pinned to a specific version and alias in the Model Registry."
                )

        except Exception as e:
            self.report['GCP'].append({"Error": str(e)})

@app.route('/scan', methods=['POST'])
def scan_endpoint():
    try:
        data = request.json
        auditor = CloudAuditor(data)
        auditor.audit_aws()
        auditor.audit_azure()
        auditor.audit_gcp()
        return jsonify(auditor.report)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)