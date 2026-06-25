from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

ALLOWED_CASE_TYPES = {
    "wrong_transfer",
    "payment_failed",
    "refund_request",
    "phishing_or_social_engineering",
    "other",
}

ALLOWED_SEVERITIES = {"low", "medium", "high", "critical"}

ALLOWED_DEPARTMENTS = {
    "customer_support",
    "dispute_resolution",
    "payments_ops",
    "fraud_risk",
}

UNSAFE_SUMMARY_PHRASES = [
    "share your otp",
    "provide your otp",
    "send your otp",
    "give your otp",
    "share pin",
    "provide pin",
    "send pin",
    "give pin",
    "share password",
    "provide password",
    "send password",
    "give password",
    "share full card number",
    "provide full card number",
]


def assert_valid_response(data, ticket_id):
    assert data["ticket_id"] == ticket_id
    assert data["case_type"] in ALLOWED_CASE_TYPES
    assert data["severity"] in ALLOWED_SEVERITIES
    assert data["department"] in ALLOWED_DEPARTMENTS
    assert isinstance(data["agent_summary"], str)
    assert len(data["agent_summary"]) > 0
    assert isinstance(data["human_review_required"], bool)
    assert isinstance(data["confidence"], (float, int))
    assert 0 <= data["confidence"] <= 1

    summary = data["agent_summary"].lower()
    for phrase in UNSAFE_SUMMARY_PHRASES:
        assert phrase not in summary


class TestHealth:
    def test_health(self):
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["service"] == "queue-storm-ticket-sorter"


class TestPublicSampleCases:
    def test_wrong_transfer(self):
        payload = {
            "ticket_id": "T-001",
            "channel": "app",
            "locale": "en",
            "message": "I sent 3000 to wrong number",
        }
        response = client.post("/sort-ticket", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert_valid_response(data, "T-001")
        assert data["case_type"] == "wrong_transfer"
        assert data["severity"] == "high"
        assert data["department"] == "dispute_resolution"
        assert data["human_review_required"] is True

    def test_payment_failed(self):
        payload = {
            "ticket_id": "T-002",
            "channel": "app",
            "locale": "en",
            "message": "Payment failed but balance deducted",
        }
        response = client.post("/sort-ticket", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert_valid_response(data, "T-002")
        assert data["case_type"] == "payment_failed"
        assert data["severity"] == "high"
        assert data["department"] == "payments_ops"

    def test_phishing(self):
        payload = {
            "ticket_id": "T-003",
            "channel": "sms",
            "locale": "en",
            "message": "Someone called asking my OTP, is that bKash?",
        }
        response = client.post("/sort-ticket", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert_valid_response(data, "T-003")
        assert data["case_type"] == "phishing_or_social_engineering"
        assert data["severity"] == "critical"
        assert data["department"] == "fraud_risk"
        assert data["human_review_required"] is True

    def test_refund(self):
        payload = {
            "ticket_id": "T-004",
            "channel": "app",
            "locale": "en",
            "message": "Please refund my last transaction, I changed my mind",
        }
        response = client.post("/sort-ticket", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert_valid_response(data, "T-004")
        assert data["case_type"] == "refund_request"
        assert data["severity"] == "low"
        assert data["department"] == "customer_support"

    def test_other(self):
        payload = {
            "ticket_id": "T-005",
            "channel": "app",
            "locale": "en",
            "message": "App crashed when I opened it",
        }
        response = client.post("/sort-ticket", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert_valid_response(data, "T-005")
        assert data["case_type"] == "other"
        assert data["severity"] == "low"
        assert data["department"] == "customer_support"


class TestPriorityCases:
    def test_phishing_priority_over_payment(self):
        payload = {
            "ticket_id": "T-006",
            "channel": "sms",
            "locale": "en",
            "message": "My payment failed and then someone called asking for my PIN",
        }
        response = client.post("/sort-ticket", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["case_type"] == "phishing_or_social_engineering"
        assert data["severity"] == "critical"
        assert data["department"] == "fraud_risk"
        assert data["human_review_required"] is True

    def test_wrong_transfer_mixed(self):
        payload = {
            "ticket_id": "T-007",
            "channel": "app",
            "locale": "mixed",
            "message": "Ami 5000 taka wrong number e send kore felsi",
        }
        response = client.post("/sort-ticket", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["case_type"] == "wrong_transfer"
        assert data["severity"] == "high"
        assert data["department"] == "dispute_resolution"


class TestBanglaCases:
    def test_bangla_wrong_transfer(self):
        payload = {
            "ticket_id": "T-008",
            "channel": "app",
            "locale": "bn",
            "message": "আমি ভুল নাম্বারে টাকা পাঠিয়েছি",
        }
        response = client.post("/sort-ticket", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["case_type"] == "wrong_transfer"
        assert data["severity"] == "high"
        assert data["department"] == "dispute_resolution"

    def test_bangla_payment_failed(self):
        payload = {
            "ticket_id": "T-009",
            "channel": "app",
            "locale": "bn",
            "message": "পেমেন্ট ফেইল হয়েছে কিন্তু টাকা কেটে গেছে",
        }
        response = client.post("/sort-ticket", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["case_type"] == "payment_failed"
        assert data["severity"] == "high"
        assert data["department"] == "payments_ops"

    def test_bangla_phishing(self):
        payload = {
            "ticket_id": "T-010",
            "channel": "sms",
            "locale": "bn",
            "message": "একজন ফোন করে আমার ওটিপি জানতে চেয়েছে",
        }
        response = client.post("/sort-ticket", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["case_type"] == "phishing_or_social_engineering"
        assert data["severity"] == "critical"
        assert data["department"] == "fraud_risk"
        assert data["human_review_required"] is True

    def test_refund_mixed(self):
        payload = {
            "ticket_id": "T-011",
            "channel": "app",
            "locale": "mixed",
            "message": "Amar last transaction er taka refund chai",
        }
        response = client.post("/sort-ticket", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["case_type"] == "refund_request"
        assert data["severity"] == "low"
        assert data["department"] == "customer_support"


class TestValidationErrors:
    def test_missing_ticket_id(self):
        payload = {
            "channel": "app",
            "locale": "en",
            "message": "Payment failed but balance deducted",
        }
        response = client.post("/sort-ticket", json=payload)
        assert response.status_code == 422

    def test_missing_message(self):
        payload = {
            "ticket_id": "T-013",
            "channel": "app",
            "locale": "en",
        }
        response = client.post("/sort-ticket", json=payload)
        assert response.status_code == 422

    def test_empty_message(self):
        payload = {
            "ticket_id": "T-014",
            "channel": "app",
            "locale": "en",
            "message": "",
        }
        response = client.post("/sort-ticket", json=payload)
        assert response.status_code == 422

    def test_invalid_channel(self):
        payload = {
            "ticket_id": "T-015",
            "channel": "facebook",
            "locale": "en",
            "message": "Payment failed",
        }
        response = client.post("/sort-ticket", json=payload)
        assert response.status_code == 422

    def test_invalid_locale(self):
        payload = {
            "ticket_id": "T-016",
            "channel": "app",
            "locale": "fr",
            "message": "Payment failed",
        }
        response = client.post("/sort-ticket", json=payload)
        assert response.status_code == 422


class TestSafety:
    def test_summary_no_otp_instruction(self):
        payload = {
            "ticket_id": "T-017",
            "channel": "sms",
            "locale": "en",
            "message": "Someone asked me for OTP",
        }
        response = client.post("/sort-ticket", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert_valid_response(data, "T-017")
        assert data["case_type"] == "phishing_or_social_engineering"
        assert data["severity"] == "critical"
        assert data["human_review_required"] is True
        summary = data["agent_summary"].lower()
        assert "share your otp" not in summary
        assert "provide your otp" not in summary
        assert "send your otp" not in summary
        assert "give your otp" not in summary

    def test_summary_no_pin_instruction(self):
        payload = {
            "ticket_id": "T-018",
            "channel": "call_center",
            "locale": "en",
            "message": "A fake agent asked for my PIN",
        }
        response = client.post("/sort-ticket", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert_valid_response(data, "T-018")
        assert data["case_type"] == "phishing_or_social_engineering"
        assert data["severity"] == "critical"
        assert data["human_review_required"] is True
        summary = data["agent_summary"].lower()
        assert "share pin" not in summary
        assert "provide pin" not in summary
        assert "send pin" not in summary
        assert "give pin" not in summary