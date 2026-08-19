"""Regression tests for issue #288.

A toolchain that cannot perform the check must not be reported as tampering.
macOS ships LibreSSL, which cannot load Ed25519 and has no -rawin, so it exits
non-zero on a perfectly intact feed.
"""

import subprocess

from prismor.runtime.audit import _is_signature_mismatch


def _completed(stdout: bytes = b"", stderr: bytes = b"", returncode: int = 1):
    return subprocess.CompletedProcess(
        args=["openssl"], returncode=returncode, stdout=stdout, stderr=stderr
    )


class TestIsSignatureMismatch:
    def test_openssl_rejection_is_a_mismatch(self):
        # Exact stdout from `openssl pkeyutl -verify` on a modified payload.
        assert _is_signature_mismatch(_completed(stdout=b"Signature Verification Failure\n"))

    def test_rejection_on_stderr_is_also_a_mismatch(self):
        assert _is_signature_mismatch(_completed(stderr=b"Signature Verification Failure\n"))

    def test_match_is_case_insensitive(self):
        assert _is_signature_mismatch(_completed(stdout=b"SIGNATURE VERIFICATION FAILURE"))

    def test_libressl_unknown_option_is_not_a_mismatch(self):
        # LibreSSL 3.3.6 has no -rawin; this is the shape of its complaint.
        result = _completed(stderr=b"pkeyutl: Unknown option: -rawin\npkeyutl: Use -help for summary.\n")
        assert not _is_signature_mismatch(result)

    def test_unsupported_algorithm_is_not_a_mismatch(self):
        result = _completed(stderr=b"Could not find private key from pub.pem\n")
        assert not _is_signature_mismatch(result)

    def test_empty_output_is_not_a_mismatch(self):
        # Grey must not render as red: no evidence is not evidence of tampering.
        assert not _is_signature_mismatch(_completed())

    def test_none_streams_do_not_raise(self):
        result = subprocess.CompletedProcess(args=["openssl"], returncode=1, stdout=None, stderr=None)
        assert not _is_signature_mismatch(result)

    def test_undecodable_bytes_do_not_raise(self):
        assert not _is_signature_mismatch(_completed(stderr=b"\xff\xfe garbage"))
