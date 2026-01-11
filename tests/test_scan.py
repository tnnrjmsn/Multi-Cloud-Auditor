import json
from unittest.mock import patch
from backend.main import app


def test_scan_endpoint_no_payload():
    """Test that missing JSON payload returns 400 error."""
    client = app.test_client()
    resp = client.post("/scan", data="")
    assert resp.status_code == 400
    data = resp.get_json()
    assert "error" in data


@patch("backend.main.CloudAuditor.audit_aws")
@patch("backend.main.CloudAuditor.audit_azure")
@patch("backend.main.CloudAuditor.audit_gcp")
def test_scan_endpoint_flow(mock_gcp, mock_azure, mock_aws):
    """Test that the scan endpoint correctly orchestrates AWS, Azure, and GCP audits."""
    client = app.test_client()
    payload = {
        "aws_access_key": "test_key",
        "aws_secret_key": "test_secret",
        "azure_client_id": "test_client",
        "gcp_json_creds": "{}"
    }
    resp = client.post(
        "/scan",
        data=json.dumps(payload),
        content_type="application/json"
    )
    assert resp.status_code == 200
    data = resp.get_json()
    
    # Verify report structure includes all cloud providers
    assert "AWS" in data
    assert "Azure" in data
    assert "GCP" in data
    
    # Verify mocked methods were called
    mock_aws.assert_called_once()
    mock_azure.assert_called_once()
    mock_gcp.assert_called_once()


@patch("backend.main.CloudAuditor.audit_aws")
@patch("backend.main.CloudAuditor.audit_azure")
@patch("backend.main.CloudAuditor.audit_gcp")
def test_scan_endpoint_with_findings(mock_gcp, mock_azure, mock_aws):
    """Test that findings are properly added to the report."""
    def add_aws_finding(self):
        self._add_finding(
            "AWS",
            "S3 Storage",
            "test-bucket",
            "Unencrypted (High Risk)",
            ["ISO 27017: CLD.8.2.1"],
            "Data at rest is readable",
            "Enable Default Encryption"
        )
    
    mock_aws.side_effect = add_aws_finding
    
    client = app.test_client()
    payload = {
        "aws_access_key": "test_key",
        "aws_secret_key": "test_secret"
    }
    resp = client.post(
        "/scan",
        data=json.dumps(payload),
        content_type="application/json"
    )
    assert resp.status_code == 200
    data = resp.get_json()
    
    # Verify finding was added
    assert len(data["AWS"]) > 0
    finding = data["AWS"][0]
    assert finding["Service"] == "S3 Storage"
    assert finding["Resource"] == "test-bucket"
    assert "Unencrypted" in finding["Status"]