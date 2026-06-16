# Metadata-Only Cloud Database Model

MongoDB Atlas is used for availability of metadata, workflow state, certificate records, and audit logs. It is not used as the repository for original PDF files or bulk ciphertext blobs.

## Stored in MongoDB Atlas

- Application owner and assigned officer IDs.
- Submission and processing status.
- Certificate serials and public-key metadata.
- Encapsulated KEM keys, nonces, algorithm names, hash values, sizes, and blob references.
- Audit events for upload, validation, signing, and verification.

## Stored Outside MongoDB

- Original uploaded PDF bytes are never persisted in the cloud database.
- Encrypted unsigned document ciphertext is stored in private blob storage.
- Encrypted signed-result ciphertext is stored in private blob storage.
- MongoDB only stores `blob_ref`, `ciphertext_sha256`, and `ciphertext_size_bytes`.

## Demo Implementation

For the local defense demo, private blob storage is a local directory configured by `PRIVATE_BLOB_STORAGE_ROOT`. In a production deployment this would map to a private object storage bucket or a managed encrypted file store with IAM, retention rules, and backup policy.

This keeps the demo aligned with the reviewer point: cloud database improves metadata availability, but leaking the database alone does not leak original document bytes.
