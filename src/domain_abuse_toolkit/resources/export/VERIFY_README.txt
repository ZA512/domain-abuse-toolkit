DOMAIN ABUSE TOOLKIT - EVIDENCE PACKAGE

This archive contains integrity-verifiable local case records.

To verify after extracting the complete archive:

    python verify_evidence.py .

To verify the ZIP directly with a separately copied verifier:

    python verify_evidence.py DAT-YYYYMMDD-XXXXXXXX.zip

A successful check prints "VERIFIED" and exits with code 0.
Keep the original ZIP unchanged. Verification proves that packaged artifacts match
their recorded SHA-256 digests; it does not independently prove the truth of a
human observation or the time at which an external event occurred.
