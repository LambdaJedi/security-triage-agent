from src.triage_agent.privacy import fingerprint, redact


def test_redacts_email_and_ip():
    text = "Reported by alice@example.com from 192.168.1.20"

    redacted, counts = redact(text)

    assert "alice@example.com" not in redacted
    assert "192.168.1.20" not in redacted
    assert counts == {"EMAIL": 1, "IPV4": 1}


def test_redacts_credential_value_but_keeps_key_name():
    redacted, counts = redact("Login used password: Hunter2!")

    assert "Hunter2!" not in redacted
    assert "password: [REDACTED:CREDENTIAL]" in redacted
    assert counts["CREDENTIAL"] == 1


def test_redacts_tokens_and_keys():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijk"
    text = (
        f"Authorization: Bearer {jwt}\n"
        "key AKIAIOSFODNN7EXAMPLE and sk-abcdefghijklmnopqrstuv"
    )

    redacted, _ = redact(text)

    assert jwt not in redacted
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted
    assert "sk-abcdefghijklmnopqrstuv" not in redacted


def test_redacts_private_key_block():
    text = (
        "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJB\n"
        "-----END RSA PRIVATE KEY-----"
    )

    redacted, counts = redact(text)

    assert "MIIBOgIBAAJB" not in redacted
    assert counts == {"PRIVATE_KEY": 1}


def test_plain_technical_text_is_unchanged():
    text = "The id parameter is concatenated into a SQL query."

    redacted, counts = redact(text)

    assert redacted == text
    assert counts == {}


def test_fingerprint_ignores_case_and_whitespace():
    assert fingerprint("SQL  injection\nfound") == fingerprint("sql injection found")
    assert fingerprint("a") != fingerprint("b")


def test_redact_structure_keeps_nested_data_valid():
    from src.triage_agent.privacy import redact_structure

    data = {
        "evidence": ["token: sk-abcdefghijklmnopqrstuv", "plain text"],
        "nested": {"contact": "bob@example.com", "count": 3},
    }

    result = redact_structure(data)

    assert "sk-abcdefghijklmnopqrstuv" not in str(result)
    assert "bob@example.com" not in str(result)
    assert result["nested"]["count"] == 3
    assert result["evidence"][1] == "plain text"
