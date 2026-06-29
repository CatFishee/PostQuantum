# PKI Architecture Reviewer Response

This file maps the reviewer concerns to concrete repository changes and demo evidence.

## 1. Public Citizen Portal

Concern: If the portal is internal only, citizens cannot upload documents.

Fix:
- The citizen portal is public over `https://thanhthuydepgai.42web.io`.
- Citizens use registration, login, upload, dashboard, and verification routes through the public HTTPS portal.
- Officer-only workflows are separated by role and device proof, not by hiding the whole portal on an intranet.

Branch and commit:
- `fix/public-citizen-portal`
- `fix: separate public citizen portal from internal officer access`

Docs:
- `docs/PORTAL_BOUNDARIES.md`

## 2. TLS 1.3 and Real Domain Demo

Concern: The demo should not be presented as `127.0.0.1`; citizens communicate safely with a server using TLS 1.3 and certificates.

Fix:
- Django allows `thanhthuydepgai.42web.io` as a real Host header.
- Apache TLS 1.3 reverse proxy config is documented.
- The local hosts-file demo keeps the browser URL as `https://thanhthuydepgai.42web.io`.

Branch and commit:
- `fix/tls13-public-portal`
- `fix: add tls 1.3 public portal deployment config`

Docs/config:
- `deployment/apache-postquantum-tls13.conf.example`
- `.env.example`

## 3. Configurable Service URLs

Concern: Hardcoded `localhost` makes the architecture look local-only.

Fix:
- Django uses `CA_SERVICE_URL` and `LOCAL_AGENT_URL` settings.
- Templates receive the Local Agent URL from Django context.
- The Local Agent allows the public demo origin and defaults to the public portal origin.

Branch and commit:
- `fix/configurable-service-urls`
- `fix: replace localhost service urls with environment config`

## 4. Cloud Database Stores Metadata, Not Original Files

Concern: Storing original documents or large ciphertext blobs directly in cloud DB can leak document content and does not explain availability correctly.

Fix:
- MongoDB Atlas stores workflow metadata, key encapsulation metadata, nonces, hashes, sizes, blob references, certificates, and audit logs.
- Encrypted document ciphertext is written to private blob storage through `PRIVATE_BLOB_STORAGE_ROOT`.
- MongoDB records only `blob_ref`, `ciphertext_sha256`, `ciphertext_size_bytes`, and policy fields.

Branch and commit:
- `fix/metadata-only-cloud-db`
- `fix: store document blobs outside mongodb metadata records`

Docs:
- `docs/STORAGE_MODEL.md`

## 5. CA/TSA Has No Document-Key Role

Concern: A CA should issue and validate certificates, not manage user keys or decrypt user documents.

Fix:
- RA runs as a separate RA Server for CSR request and approval state.
- CA/TSA responsibilities are limited to certificate issuing after RA approval, OCSP/CRL, TSA timestamping, and signature verification metadata.
- The CA no longer re-encrypts signed artifacts with its master KEM for storage.
- Signed PDFs are delivered by portal delivery storage after CA verification, so citizens can download a signed artifact without the CA acting as a decryptor.
- `/decrypt-pdf` returns HTTP 410 and explains that document decryption must happen on an authorized user/officer device.

Branch and commit:
- `fix/ca-not-kms`
- `fix: limit ca server to certificate tsa and revocation duties`

Docs:
- `docs/CA_TSA_BOUNDARY.md`

## 6. Officer Device Authentication

Concern: Digital signing should not require sitting in the office; it should prove possession of an authorized device/key.

Fix:
- Office-IP checks were removed from officer registration, login, signing, decrypt, and Local Agent proxy paths.
- Django creates a device challenge with `/api/device-challenge/`.
- PQC Local Agent signs the challenge with the local ML-DSA private key through `/api/device-proof`.
- Django verifies that proof with `/api/device-verify/` and a short-lived session timestamp.

Branch and commit:
- `fix/officer-device-auth`
- `fix: require officer device challenge instead of office ip`

Docs:
- `docs/OFFICER_DEVICE_AUTH.md`

## Demo Notes

For the current local defense demo:

1. `thanhthuydepgai.42web.io` is mapped to `127.0.0.1` in the Windows hosts file.
2. Apache terminates TLS 1.3 using the ZeroSSL ECDSA certificate for `thanhthuydepgai.42web.io`.
3. Apache reverse-proxies to Django on `127.0.0.1:8000`.
4. The CA/TSA service runs on `127.0.0.1:5001`.
5. The RA Server runs on `127.0.0.1:5002`.
6. The PQC Local Agent runs on `127.0.0.1:54321`.

This is a local deployment pattern for demonstrating the real domain, certificate, SNI, TLS 1.3, PKI flow, metadata-only cloud database design, and device-bound officer signing without needing a public VM or production HSM.
