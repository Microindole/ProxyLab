from proxy_traffic_lab.security.redaction import redact, stable_hash


def test_hash_does_not_expose_input() -> None:
    value = "203.0.113.10"
    result = stable_hash(value)
    assert result.startswith("sha256:")
    assert value not in result


def test_redacts_uuid_and_password() -> None:
    text = (
        "password=correct-horse "
        "id=123e4567-e89b-42d3-a456-426614174000"
    )
    result = redact(text)
    assert "correct-horse" not in result
    assert "123e4567" not in result

