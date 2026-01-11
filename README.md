# Multi-Framework Cloud Auditor

A lightweight, secure, and serverless tool to audit **AWS**, **Azure**, and **GCP** environments. This tool assists in the "Asset Inventory" and "Operational Control" requirements for multiple ISO standards, focusing on AI Governance, Cloud Security, and Privacy.

## 🏗 Architecture

* **Backend**: Python (Flask) running on **Google Cloud Run**. It scales to zero when not in use ($0 cost when idle).
* **Frontend**: A simple local **HTML/JS** file. No hosting required.
* **Security**: Secured via **Google IAM**. Requires a valid OIDC ID Token to invoke the API, preventing unauthorized access and bot traffic.

## 🚀 Prerequisites

1.  **Google Cloud Account** (Free tier is sufficient).
2.  **gcloud CLI** installed and authenticated.
3.  **Python 3.9+** (for local development/testing).

## 📦 Installation (Local Development)

```bash
pip install -r requirements.txt
```

## 🛠 Deployment (Backend)

We deploy the Python backend to Google Cloud Run.

1.  **Clone this repo** and navigate to the `backend` folder.
2.  **Deploy using Cloud Build** (No local Docker required):

    ```bash
    gcloud run deploy cloud-auditor \
      --source . \
      --platform managed \
      --region us-central1 \
      --no-allow-unauthenticated \
      --memory 512Mi
    ```

    *Note: The `--no-allow-unauthenticated` flag ensures only users with valid Google credentials can access your API.*

3.  **Copy the URL** output by the command (e.g., `https://cloud-auditor-xyz.run.app`).

## 🖥 Usage (Frontend)

1.  Open `frontend/index.html` in your web browser.
2.  **Generate a Security Token**:
    Since the backend is private, you need a temporary ID token. Run this in your terminal:

    ```bash
    gcloud auth print-identity-token
    ```

    *Tokens are valid for 1 hour.*

3.  **Fill out the UI**:
    * **Cloud Run URL**: Paste the URL from the deployment step.
    * **Google ID Token**: Paste the token generated above.
    * **Cloud Credentials**: Enter Read-Only keys for the clouds you want to scan.
4.  Click **Run Secure Audit Scan**.

## 🔍 Debugging

### Local Development
To run the backend locally:
```bash
python backend/main.py
```
The API will be available at `http://localhost:8080/scan`.

### Cloud Run Logs
To monitor audit execution and troubleshoot in production:
```bash
gcloud run logs read cloud-auditor --region us-central1 --limit 50
```
The backend logs all audit steps, credential validation, and errors for visibility into cloud scanning operations.

### Debug Mode
Enable debug logging locally:
```bash
DEBUG=true python backend/main.py
```

## 🛡 Compliance Framework Alignment

This tool maps discovered assets and configurations to specific controls across four major ISO standards.

| Framework | Control / Clause | Description | How this tool helps |
| :--- | :--- | :--- | :--- |
| **ISO 42001** | **6.1** | **Actions to address risks** | Automates the discovery of "Shadow AI" or undocumented AI assets (SageMaker, Vertex AI, Azure AI). |
| **ISO 42001** | **8.2** | **AI Risk Assessment** | Identifies if AI development notebooks are exposed or running in production states without controls. |
| **ISO 42001** | **9.1** | **Monitoring & Evaluation** | Verifies if AI services (like Azure OpenAI) have logging/diagnostic settings enabled for audit trails. |
| **ISO 27017** | **CLD.8.2.1** | **Info Security in Storage** | Scans S3 buckets and Storage Accounts to ensure default encryption is enabled. |
| **ISO 27017** | **CLD.9.5** | **Segregation in Networks** | Audits Security Groups and Firewalls to detect unrestricted traffic (0.0.0.0/0) on management ports. |
| **ISO 27018** | **PII Protection** | **Public Cloud Privacy** | Checks for public exposure of databases and storage where PII might reside. |
| **ISO 27001** | **A.13.1** | **Network Security Management** | Flags open ports (SSH/RDP) that increase the attack surface for intruders. |
| **ISO 27001** | **A.10.1** | **Cryptographic Controls** | Checks SQL Databases for Transparent Data Encryption (TDE) to protect confidentiality. |

## ⚠️ Security Notice

* **Credentials**: This tool transmits cloud credentials (AWS Keys, Azure Secrets) to the backend. While the transmission is over HTTPS, **credentials are never stored** on the server. They are used for the duration of the request and discarded.
* **Best Practice**: Always use **Read-Only** service accounts/principals for auditing purposes.

## 📄 License

MIT
