"""An MCP result carries its payload twice; masking one copy is not masking.

Servers built on the MCP SDK's output schemas return the same data as
``content[].text`` AND as ``structuredContent``. Redacting only the text copy
hands a client that prefers the structured one the raw credential.
"""
from prismor.runtime.redaction import redact_mcp_result

SECRET = "sk_live_" + "0123456789abcdefXYZ"


def test_structured_content_is_redacted_alongside_text():
    result = {
        "content": [{"type": "text", "text": f"STRIPE_SECRET_KEY={SECRET}"}],
        "structuredContent": {"content": f"STRIPE_SECRET_KEY={SECRET}"},
    }
    out, changed = redact_mcp_result(result, data_boundary=True)
    assert changed
    assert SECRET not in str(out)


def test_structured_content_alone_is_still_redacted():
    """No text blocks at all — the structured copy is the only leak path."""
    out, changed = redact_mcp_result(
        {"structuredContent": {"rows": [{"key": SECRET}]}}, data_boundary=True)
    assert changed
    assert SECRET not in str(out)


def test_structured_keys_survive_redaction():
    """Values are masked; the schema the client parses against is not."""
    out, _ = redact_mcp_result(
        {"structuredContent": {"STRIPE_SECRET_KEY": SECRET}}, data_boundary=True)
    assert list(out["structuredContent"]) == ["STRIPE_SECRET_KEY"]


def test_clean_result_passes_through_untouched():
    result = {"content": [{"type": "text", "text": "no secrets here"}],
              "structuredContent": {"ok": True, "n": 3}}
    out, changed = redact_mcp_result(result, data_boundary=True)
    assert not changed and out is result


def test_non_mcp_shapes_are_unchanged():
    for value in ({}, {"foo": "bar"}, "text", None, 7):
        out, changed = redact_mcp_result(value)
        assert not changed and out == value
