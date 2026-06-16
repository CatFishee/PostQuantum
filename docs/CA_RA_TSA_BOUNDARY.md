# CA/RA/TSA Boundary

The CA service is not a KMS and does not manage user private keys.

## Responsibilities Kept in the CA/RA/TSA Service

- Issue officer certificates after RA registration checks.
- Sign certificate bodies with the CA signing key.
- Publish OCSP and CRL status for certificates.
- Issue TSA timestamp tokens for document hashes.
- Verify a submitted signed PDF and record verification metadata.

## Responsibilities Removed from the CA Service

- No document download/decrypt endpoint for completed artifacts.
- No storage encryption using the CA master KEM.
- No escrow or recovery of officer/citizen private keys.
- No use of CA private material to decrypt user documents for normal access.

The `/master-public-key` endpoint remains only as a CA transport key for encrypted requests into the CA service. Its response marks the key purpose as `ca-transport-only`.

## Demo Consequence

After signature verification, the database stores proof metadata such as document hash, certificate serial, and verification time. The signed artifact must be distributed through an authorized device-side or storage-side workflow, not by asking the CA to decrypt and return it.
