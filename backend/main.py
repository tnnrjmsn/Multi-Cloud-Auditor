import os
import json
import boto3
from flask import Flask, request, jsonify
from flask_cors import CORS
from azure.identity import ClientSecretCredential
from azure.mgmt.cognitiveservices import CognitiveServicesManagementClient
from google.cloud import aiplatform
from google.oauth2 import service_account

# Initialize Flask App
app = Flask(__name__)

# ENABLE CORS: This is critical. It allows your local HTML file (file://...) 
# to make POST requests to this remote Cloud Run domain.
CORS(app)

class CloudAuditor:
    """
    The main logic class that connects to various cloud providers
    to discover AI assets for ISO/IEC 42001 inventory purposes.
    """
    def __init__(self, credentials):
        self.creds = credentials
        # The report structure separates assets by provider
        self.report = {"AWS": [], "Azure": [], "GCP": []}

    def audit_aws(self):
        """
        Scans AWS for SageMaker and Bedrock resources.
        ISO 42001 Clause 6.1: AI System Impact Assessment (Inventory).
        """
        if not self.creds.get('aws_access_key'): return
        
        try:
            session = boto3.Session(
                aws_access_key_id=self.creds['aws_access_key'],
                aws_secret_access_key=self.creds['aws_secret_key'],
                region_name=self.creds.get('aws_region', 'us-east-1')
            )
            
            # --- Check 1: SageMaker Notebooks ---
            # Notebooks often contain experimental data. 
            # We check if they are 'InService' to assess exposure.
            sm = session.client('sagemaker')
            notebooks = sm.list_notebook_instances()
            for nb in notebooks.get('NotebookInstances', []):
                self.report['AWS'].append({
                    "Service": "SageMaker Notebook",
                    "Resource": nb['NotebookInstanceName'],
                    "Status": nb['NotebookInstanceStatus'],
                    "ISO_Alignment": "Clause 8.2 (Risk Treatment): Ensure dev environments are isolated."
                })

            # --- Check 2: Bedrock (GenAI) ---
            # Discovery of Foundation Models usage.
            # Note: Bedrock API access depends on specific region enablement.
            try:
                bedrock = session.client('bedrock')
                models = bedrock.list_foundation_models()
                if models.get('modelSummaries'):
                     self.report['AWS'].append({
                        "Service": "Bedrock Foundation Model",
                        "Status": "Active Access",
                        "ISO_Alignment": "Clause 5.2: Ensure usage aligns with AI Policy."
                    })
            except Exception:
                # Bedrock might not be enabled or available in this region
                pass

        except Exception as e:
            self.report['AWS'].append({"Error": f"AWS Scan Failed: {str(e)}"})

    def audit_azure(self):
        """
        Scans Azure for Cognitive Services (OpenAI, Vision, etc.).
        ISO 42001 Clause 9.1: Monitoring, measurement, analysis, and evaluation.
        """
        if not self.creds.get('azure_client_id'): return

        try:
            credential = ClientSecretCredential(
                tenant_id=self.creds['azure_tenant_id'],
                client_id=self.creds['azure_client_id'],
                client_secret=self.creds['azure_client_secret']
            )
            client = CognitiveServicesManagementClient(credential, self.creds['azure_subscription_id'])

            # List all AI accounts (OpenAI, Face API, Speech, etc.)
            accounts = client.accounts.list()
            for account in accounts:
                self.report['Azure'].append({
                    "Service": account.kind,  # e.g., OpenAI, Face, SpeechServices
                    "Resource": account.name,
                    "Location": account.location,
                    "ISO_Alignment": "Clause 9.1: Verify Diagnostic Settings are pushing logs to Azure Monitor."
                })

        except Exception as e:
            self.report['Azure'].append({"Error": f"Azure Scan Failed: {str(e)}"})

    def audit_gcp(self):
        """
        Scans Google Cloud for Vertex AI Models.
        ISO 42001 Clause 8: Operation (Data Lineage and Versioning).
        """
        if not self.creds.get('gcp_json_creds'): return

        try:
            # Parse the JSON key provided by the user
            gcp_info = json.loads(self.creds['gcp_json_creds'])
            credentials = service_account.Credentials.from_service_account_info(gcp_info)
            
            # Initialize Vertex AI SDK
            aiplatform.init(
                project=gcp_info['project_id'],
                credentials=credentials
            )

            # List models in the registry
            models = aiplatform.Model.list()
            for model in models:
                self.report['GCP'].append({
                    "Service": "Vertex AI Model",
                    "Resource": model.display_name,
                    "Updated": str(model.update_time),
                    "ISO_Alignment": "Clause 8: Verify model versioning and training data lineage."
                })

        except Exception as e:
            self.report['GCP'].append({"Error": f"GCP Scan Failed: {str(e)}"})

@app.route('/scan', methods=['POST'])
def scan_endpoint():
    """
    Main API Endpoint.
    1. Receives JSON payload with cloud credentials.
    2. Instantiates CloudAuditor.
    3. Runs scans sequentially.
    4. Returns JSON report.
    """
    try:
        data = request.json
        if not data:
            return jsonify({"error": "No data provided"}), 400

        auditor = CloudAuditor(data)
        
        # Run audits (Errors are caught internally and added to the report)
        auditor.audit_aws()
        auditor.audit_azure()
        auditor.audit_gcp()
        
        return jsonify(auditor.report)

    except Exception as e:
        return jsonify({"error": f"Server Error: {str(e)}"}), 500

if __name__ == "__main__":
    # Cloud Run automatically injects the PORT environment variable.
    # We default to 8080 if running locally.
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)