# ISO/IEC 42001:2023 Multi-Cloud AI Auditor

A lightweight, secure, and serverless tool to discover AI/ML assets across **AWS**, **Azure**, and **GCP**. This tool aids in the "Asset Inventory" and "Operational Control" requirements of the **ISO 42001 (Artificial Intelligence Management System)** standard.

## 🏗 Architecture

* **Backend**: Python (Flask) running on **Google Cloud Run**. It scales to zero when not in use ($0 cost when idle).
* **Frontend**: A simple local **HTML/JS** file. No hosting required.
* **Security**: Secured via **Google IAM**. Requires a valid OIDC ID Token to invoke the API, preventing unauthorized access and bot traffic.

## 🚀 Prerequisites

1.  **Google Cloud Account** (Free tier is sufficient).
2.  **gcloud CLI** installed and authenticated.
3.  **Docker** (Optional, only if testing backend locally).

## 🛠 Deployment (Backend)

We deploy the Python backend to Google Cloud Run.

1.  **Clone this repo** and navigate to the `backend` folder.
2.  **Deploy using Cloud Build** (No local Docker required):
    ```bash
    gcloud run deploy iso-auditor \
      --source . \
      --platform managed \
      --region us-central1 \
      --no-allow-unauthenticated \
      --memory 512Mi
    ```
    *Note: The `--no-allow-unauthenticated` flag ensures only users with valid Google credentials can access your API.*

3.  **Copy the URL** output by the command (e.g., `https://iso-auditor-xyz.run.app`).

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

## 🛡 ISO 42001 Alignment

This tool assists with the following clauses:

| Clause | Description | How this tool helps |
| :--- | :--- | :--- |
| **6.1** | **Actions to address risks** | Automates the discovery of "Shadow AI" or undocumented AI assets (SageMaker, Vertex AI, etc.). |
| **8.2** | **AI Risk Assessment** | Identifies if development notebooks are exposed or running in production states. |
| **9.1** | **Monitoring & Evaluation** | Checks if AI services (like Azure OpenAI) have logging/diagnostics enabled. |

## ⚠️ Security Notice

* **Credentials**: This tool transmits cloud credentials (AWS Keys, Azure Secrets) to the backend. While the transmission is over HTTPS, **credentials are never stored** on the server. They are used for the duration of the request and discarded.
* **Best Practice**: Always use **Read-Only** service accounts/principals for auditing purposes.

## 📄 License
MIT