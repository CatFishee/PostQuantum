# CA/TSA Boundary

The CA/TSA service is not a key-management or document-decryption service. It does not store user private keys, recover user keys, or decrypt citizen/officer documents for normal access.

The Registration Authority runs as a separate RA Server on `127.0.0.1:5002`. The public portal provides the admin UI, but officer CSR creation, CSR review state, and approval/rejection decisions are handled by the RA Server.

## CA/TSA Responsibilities

- Issue officer certificates only after receiving an approved request from the RA Server.
- Sign certificate bodies with the CA signing key.
- Publish OCSP and CRL status for certificates.
- Issue TSA timestamp tokens for document hashes.
- Verify submitted signed PDF metadata and record verification proof.

## RA Responsibilities

- Receive officer CSR requests from the portal after officer registration.
- Store pending certificate requests in MongoDB.
- Let an admin approve or reject the CSR through the portal UI.
- Call the CA/TSA certificate issuing endpoint only after admin approval.
- Activate or keep inactive the officer account based on the review decision.

## Responsibilities Excluded From CA/TSA

- No document download/decrypt endpoint for completed artifacts.
- No storage encryption using CA signing or transport material.
- No escrow or recovery of officer/citizen private keys.
- No use of CA private material to decrypt user documents for normal access.

The `/master-public-key` endpoint remains only as a CA transport key for encrypted service-to-service requests into the CA/TSA service. Its response marks the key purpose as `ca-transport-only`.

## Demo Consequence

After signature verification, the database stores proof metadata such as document hash, certificate serial, and verification time. The signed artifact is distributed by the portal delivery store (`media/signed_results` in the local demo), not by asking CA/TSA to decrypt and return it.
