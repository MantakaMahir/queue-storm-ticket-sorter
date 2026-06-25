PHISHING_KEYWORDS = [
    "otp",
    "pin",
    "password",
    "verification code",
    "login code",
    "security code",
    "full card number",
    "card number",
    "cvv",
    "scam",
    "fraud",
    "phishing",
    "suspicious",
    "someone called",
    "asked for code",
    "bkash agent asked",
    "account blocked",
    "prize",
    "lottery",
    "ওটিপি",
    "পিন",
    "পাসওয়ার্ড",
    "পাসওয়ার্ড",
    "কোড",
    "ভেরিফিকেশন",
    "প্রতারক",
    "স্ক্যাম",
    "জালিয়াতি",
    "জালিয়াতি",
]

WRONG_TRANSFER_KEYWORDS = [
    "wrong number",
    "wrong recipient",
    "wrong account",
    "sent to wrong",
    "mistakenly sent",
    "mistake transfer",
    "wrongly sent",
    "sent money by mistake",
    "recover money",
    "get it back",
    "ভুল নাম্বার",
    "ভুল নম্বর",
    "ভুলে পাঠিয়েছি",
    "ভুলে পাঠিয়েছি",
    "ভুল অ্যাকাউন্ট",
    "টাকা ফেরত চাই",
    "ভুলে সেন্ড",
]

PAYMENT_FAILED_KEYWORDS = [
    "payment failed",
    "transaction failed",
    "failed transaction",
    "balance deducted",
    "money deducted",
    "amount deducted",
    "deducted but",
    "charged but failed",
    "payment not successful",
    "merchant payment failed",
    "send money failed",
    "cash out failed",
    "পেমেন্ট ফেইল",
    "পেমেন্ট ফেল",
    "ট্রানজেকশন ফেইল",
    "টাকা কেটে গেছে",
    "ব্যালেন্স কেটে গেছে",
    "কেটে নিয়েছে",
    "সফল হয়নি",
]

REFUND_KEYWORDS = [
    "refund",
    "refund request",
    "return my money",
    "money back",
    "cancel transaction",
    "reverse transaction",
    "changed my mind",
    "want refund",
    "need refund",
    "রিফান্ড",
    "টাকা ফেরত",
    "ফেরত চাই",
    "লেনদেন বাতিল",
    "ক্যানসেল",
    "বাতিল করতে চাই",
]

UNSAFE_PHRASES = [
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


def normalize_text(text: str) -> str:
    return " ".join(text.lower().strip().split())


def contains_any(text: str, keywords: list[str]) -> bool:
    return any(keyword in text for keyword in keywords)


def sanitize_summary(summary: str) -> str:
    lower = summary.lower()
    for phrase in UNSAFE_PHRASES:
        if phrase in lower:
            return "Customer reports a sensitive account issue that requires human review."
    return summary


def classify_ticket(ticket_id: str, message: str) -> dict:
    text = normalize_text(message)

    if contains_any(text, PHISHING_KEYWORDS):
        return sanitize_response({
            "ticket_id": ticket_id,
            "case_type": "phishing_or_social_engineering",
            "severity": "critical",
            "department": "fraud_risk",
            "agent_summary": "Customer reports a suspicious contact or request for sensitive account information and needs fraud review.",
            "human_review_required": True,
            "confidence": 0.95,
        })

    if contains_any(text, WRONG_TRANSFER_KEYWORDS):
        return sanitize_response({
            "ticket_id": ticket_id,
            "case_type": "wrong_transfer",
            "severity": "high",
            "department": "dispute_resolution",
            "agent_summary": "Customer reports sending money to a wrong number or recipient and requests recovery support.",
            "human_review_required": True,
            "confidence": 0.85,
        })

    if contains_any(text, PAYMENT_FAILED_KEYWORDS):
        return sanitize_response({
            "ticket_id": ticket_id,
            "case_type": "payment_failed",
            "severity": "high",
            "department": "payments_ops",
            "agent_summary": "Customer reports a failed payment or transaction where balance may have been deducted.",
            "human_review_required": False,
            "confidence": 0.85,
        })

    if contains_any(text, REFUND_KEYWORDS):
        return sanitize_response({
            "ticket_id": ticket_id,
            "case_type": "refund_request",
            "severity": "low",
            "department": "customer_support",
            "agent_summary": "Customer requests a refund or reversal for a recent transaction.",
            "human_review_required": False,
            "confidence": 0.75,
        })

    return sanitize_response({
        "ticket_id": ticket_id,
        "case_type": "other",
        "severity": "low",
        "department": "customer_support",
        "agent_summary": "Customer reports a general app or service issue.",
        "human_review_required": False,
        "confidence": 0.60,
    })


def sanitize_response(response: dict) -> dict:
    response["agent_summary"] = sanitize_summary(response["agent_summary"])
    return response
