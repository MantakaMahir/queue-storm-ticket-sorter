from app.classifier import contains_any, normalize_text, sanitize_summary, classify_ticket


class TestNormalize:
    def test_lowercase(self):
        assert normalize_text("HELLO") == "hello"

    def test_extra_whitespace(self):
        assert normalize_text("  hello   world  ") == "hello world"


class TestContainsAny:
    def test_match_found(self):
        assert contains_any("hello world", ["world"]) is True

    def test_match_not_found(self):
        assert contains_any("hello world", ["foo"]) is False

    def test_partial_substring_match(self):
        assert contains_any("wrong number e", ["wrong number"]) is True

    def test_bangla_substring(self):
        assert contains_any("ভুল নাম্বারে টাকা", ["ভুল নাম্বার"]) is True


class TestSanitizeSummary:
    def test_safe_returns_unchanged(self):
        result = sanitize_summary("Customer reports a general issue.")
        assert result == "Customer reports a general issue."

    def test_unsafe_replaced(self):
        result = sanitize_summary("Please share your otp with us.")
        assert result == "Customer reports a sensitive account issue that requires human review."

    def test_neutral_mention_allowed(self):
        summary = "Customer reports a suspicious request for OTP/PIN and needs fraud review."
        result = sanitize_summary(summary)
        assert result == summary


class TestClassifyTicket:
    def test_phishing(self):
        result = classify_ticket("T-1", "Someone called asking my OTP")
        assert result["case_type"] == "phishing_or_social_engineering"
        assert result["severity"] == "critical"
        assert result["department"] == "fraud_risk"
        assert result["human_review_required"] is True
        assert result["confidence"] == 0.95

    def test_wrong_transfer(self):
        result = classify_ticket("T-2", "I sent money to wrong number")
        assert result["case_type"] == "wrong_transfer"
        assert result["severity"] == "high"
        assert result["department"] == "dispute_resolution"

    def test_payment_failed(self):
        result = classify_ticket("T-3", "Payment failed but balance deducted")
        assert result["case_type"] == "payment_failed"
        assert result["severity"] == "high"
        assert result["department"] == "payments_ops"

    def test_refund(self):
        result = classify_ticket("T-4", "I want a refund please")
        assert result["case_type"] == "refund_request"
        assert result["severity"] == "low"
        assert result["department"] == "customer_support"

    def test_other(self):
        result = classify_ticket("T-5", "App not loading")
        assert result["case_type"] == "other"
        assert result["severity"] == "low"
        assert result["department"] == "customer_support"

    def test_phishing_priority(self):
        result = classify_ticket("T-6", "Payment failed and someone asked for my PIN")
        assert result["case_type"] == "phishing_or_social_engineering"

    def test_ticket_id_echo(self):
        result = classify_ticket("T-ABC", "general question")
        assert result["ticket_id"] == "T-ABC"
