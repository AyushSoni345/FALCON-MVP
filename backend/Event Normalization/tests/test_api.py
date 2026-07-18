from fastapi import status
from tests.test_normalizers import create_mock_uee

def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["status"] == "healthy"

def test_schema_endpoint(client):
    response = client.get("/schema")
    assert response.status_code == status.HTTP_200_OK
    assert "supported_parsers" in response.json()

def test_normalize_single_event(client):
    raw_payload = {
        "SRC_IP": "185.220.101.5",
        "DST_IP": "10.0.1.5",
        "SOURCE_PORT": "49120",
        "DESTINATION_PORT": "443",
        "PROTOCOL": "TCP",
        "ACTION": "BLOCK",
        "RULE_ID": "fw-1"
    }
    uee = create_mock_uee(
        "FIREWALL", raw_payload, source_ip="185.220.101.5", destination_ip="10.0.1.5",
        correlation_id="corr-999"
    )
    
    response = client.post("/normalize", json=uee)
    assert response.status_code == status.HTTP_200_OK
    
    data = response.json()
    assert data["event_information"]["correlation_id"] == "corr-999"
    assert data["geo_context"]["country"] == "Germany"
    assert data["threat_context"]["IOC_match"] is True

def test_normalize_single_event_unsupported_parser(client):
    raw_payload = {"some_data": "invalid"}
    uee = create_mock_uee("INVALID_LOG_TYPE_123", raw_payload)
    
    response = client.post("/normalize", json=uee)
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    
    data = response.json()
    assert data["error_code"] == "UNSUPPORTED_EVENT_TYPE"
    assert "INVALID_LOG_TYPE_123" in data["error_message"]
    assert data["processing_stage"] == "parser_selection"
    assert data["recommended_action"] != ""

def test_normalize_single_event_invalid_schema(client):
    # Pass an incomplete metadata envelope payload causing UEE validation failure
    bad_payload = {
        "metadata": {
            "event_uuid": "mock-uuid-1",
            "event_type": "FIREWALL"
            # Missing ingestion_timestamp, original_timestamp, source_system, event_hash etc.
        },
        "raw_payload": {}
    }
    response = client.post("/normalize", json=bad_payload)
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

def test_normalize_batch_events(client):
    raw_payload1 = {
        "Client_IP": "8.8.8.8",
        "VPN Gateway": "vpn-gw-india",
        "Authentication": "SUCCESS",
        "MFA": "DUO_PUSH",
        "DeviceID": "DEV-LAPTOP-5"
    }
    uee1 = create_mock_uee(
        "VPN", raw_payload1, correlation_id="batch-corr-1", username="alice_user", device_id="DEV-LAPTOP-5"
    )

    raw_payload2 = {
        "Transaction_ID": "TXN_77261",
        "UPI_ID": "alice@okhdfc",
        "Sender_Account": "ACC-9901",
        "Receiver_UPI": "bob@okaxis",
        "Amount": "25000",
        "Status": "SUCCESS"
    }
    uee2 = create_mock_uee(
        "UPI", raw_payload2, correlation_id="batch-corr-2", customer_id="CUST-9901", account_number="ACC-9901"
    )

    payload = [uee1, uee2]
    
    response = client.post("/normalize/batch", json=payload)
    assert response.status_code == status.HTTP_200_OK
    
    data = response.json()
    assert len(data) == 2
    assert data[0]["event_information"]["correlation_id"] == "batch-corr-1"
    assert data[0]["identity_context"]["username"] == "alice_user"
    assert data[0]["asset_context"]["device_type"] == "VPN Gateway"
    
    assert data[1]["event_information"]["correlation_id"] == "batch-corr-2"
    assert data[1]["financial_context"]["amount"] == 25000.0
    assert data[1]["financial_context"]["payment_channel"] == "UPI"

def test_normalize_batch_events_mixed_success_failure(client):
    raw_payload1 = {
        "Client_IP": "8.8.8.8",
        "VPN Gateway": "vpn-gw-india",
        "Authentication": "SUCCESS",
        "MFA": "DUO_PUSH",
        "DeviceID": "DEV-LAPTOP-5"
    }
    uee1 = create_mock_uee(
        "VPN", raw_payload1, correlation_id="batch-corr-1", username="alice_user", device_id="DEV-LAPTOP-5"
    )

    # uee2 has unsupported event type and will fail
    uee2 = create_mock_uee(
        "INVALID_LOG_TYPE", {"test": 123}, correlation_id="batch-corr-2"
    )

    payload = [uee1, uee2]
    
    response = client.post("/normalize/batch", json=payload)
    assert response.status_code == 207  # Multi-Status code
    
    data = response.json()
    assert len(data) == 2
    assert "event_information" in data[0]
    assert data[0]["event_information"]["correlation_id"] == "batch-corr-1"
    
    assert "error_code" in data[1]
    assert data[1]["error_code"] == "UNSUPPORTED_EVENT_TYPE"
    assert data[1]["processing_stage"] == "parser_selection"

def test_metrics_endpoint(client):
    raw_payload = {
        "SRC_IP": "106.51.78.23",
        "DST_IP": "10.0.1.5",
        "SOURCE_PORT": "52210",
        "DESTINATION_PORT": "443",
        "PROTOCOL": "TCP",
        "ACTION": "ALLOW",
        "RULE_ID": "allow-rule"
    }
    uee = create_mock_uee("FIREWALL", raw_payload, source_ip="106.51.78.23")
    client.post("/normalize", json=uee)
    
    response = client.get("/metrics")
    assert response.status_code == status.HTTP_200_OK
    
    metrics = response.json()
    assert metrics["events_processed"] >= 1
    assert "FirewallParser" in metrics["parser_statistics"]
    assert metrics["geo_lookup_count"] >= 1
