# PostQuantum — Post-Quantum PKI Document Signing System

A demo-scale **Public Key Infrastructure (PKI) and document signing platform** built entirely on **NIST-standardized post-quantum cryptography** (ML-KEM / ML-DSA, the FIPS 203/204 algorithms formerly known as Kyber and Dilithium). It models a real-world "citizen ↔ government officer" administrative workflow: citizens upload PDF applications, officers review and digitally sign them with quantum-resistant signatures, and a certificate authority issues, verifies, and revokes officer certificates — all without ever centralizing anyone's private keys.

The project is a **multi-service architecture** (one Django web portal + three Python microservices) intentionally split so that no single component has both the authority to issue certificates *and* the ability to decrypt user documents.

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Repository Structure](#repository-structure)
- [Services in Detail](#services-in-detail)
  - [PublicAdminWeb (Django Portal)](#1-publicadminweb--django-portal)
  - [CA-TSA Server](#2-ca-tsa-server--certificate-authority--timestamping-authority)
  - [RA Server](#3-ra-server--registration-authority)
  - [PQC Local Agent](#4-pqc-local-agent--pqc_agentpy)
- [Cryptography](#cryptography)
- [Core Workflows](#core-workflows)
- [Data & Storage Model](#data--storage-model)
- [Trust Boundaries & Security Design](#trust-boundaries--security-design)
- [Tech Stack](#tech-stack)
- [Setup & Running Locally](#setup--running-locally)
- [Configuration (Environment Variables)](#configuration-environment-variables)
- [Known Demo Limitations](#known-demo-limitations)
- [Project History](#project-history)

---

## Architecture Overview

The system is composed of **four independent processes** that communicate over HTTP/HTTPS, each with a narrow, deliberately scoped responsibility:

```
                         Citizens & Officers (browser)
                                    │
                                    │  HTTPS (TLS 1.3, Apache reverse proxy)
                                    ▼
                     ┌───────────────────────────────┐
                     │   PublicAdminWeb (Django)      │  Port 8000
                     │   Public citizen/officer portal│
                     └───────────────┬─────┬──────────┘
                                      │     │
                      RA_SERVICE_URL │     │ CA_SERVICE_URL
                                      ▼     ▼
                     ┌───────────────────┐ ┌──────────────────────┐
                     │   RA Server        │ │   CA-TSA Server       │  Ports 5002 / 5001
                     │   (FastAPI)        │ │   (FastAPI)            │
                     │   CSR intake &     │─▶  Certificate issuing,  │
                     │   admin review     │ │   OCSP/CRL, TSA,       │
                     └───────────────────┘ │   PDF encrypt/verify   │
                                            └───────────┬───────────┘
                                                         │
                                                         ▼
                                              MongoDB Atlas (metadata only)
                                              + local private blob storage

                     ┌───────────────────────────────┐
                     │  PQC Local Agent (FastAPI)      │  Port 54321 (runs on the officer's own machine)
                     │  Holds the officer's PQC private│
                     │  keys, signs & decrypts locally │
                     └───────────────────────────────┘
```

Key architectural principle (see `docs/CA_TSA_BOUNDARY.md` and `docs/OFFICER_DEVICE_AUTH.md`): **the CA never holds a user's document-decryption key, and an officer's signing/decryption private key never leaves their own machine.** The Django portal and MongoDB only ever see ciphertext and metadata.

---

## Repository Structure

```
postquantum/
├── PublicAdminWeb/            # Django 5 web portal (citizen + officer + admin UI)
│   ├── PublicAdminWeb/         # Django project package (settings, urls, wsgi)
│   ├── app/                    # Main Django app
│   │   ├── views.py             # All page + API view logic (~835 lines)
│   │   ├── forms.py             # Signature/upload/decrypt forms
│   │   ├── crypto_utils.py      # AES-GCM helpers, SHAKE-256 PDF hashing, PAdES-style signature embedding
│   │   ├── db_connection.py     # MongoDB Atlas connection helper
│   │   ├── models.py            # (empty — data is stored in MongoDB, not Django ORM)
│   │   ├── management/commands/seed_demo_admin.py  # Seeds a demo admin account
│   │   ├── templates/app/       # Server-rendered HTML templates (Bootstrap-based)
│   │   ├── static/app/          # Bootstrap/jQuery static assets
│   │   └── media/                # Uploaded/encrypted/signed PDFs (demo local storage)
│   ├── manage.py
│   └── db.sqlite3               # Django's own DB (sessions/admin only — app data lives in MongoDB)
│
├── CA-TSA Server/              # FastAPI service — Certificate Authority + Timestamping Authority
│   ├── main.py                  # All CA/TSA endpoints
│   ├── crypto_utils.py          # AES-GCM helpers for CA transport encryption
│   ├── db_connection.py         # MongoDB connection
│   ├── ca_hsm_secured.json      # Encrypted-at-rest CA master keypairs (simulated HSM)
│   ├── master_ca_public.key / master_ca_private.key
│   └── oqs.dll                  # liboqs native library (Windows)
│
├── RA Server/                  # FastAPI service — Registration Authority
│   ├── main.py                  # CSR intake, admin approve/reject, calls CA to issue certs
│   └── db_connection.py
│
├── pqc_agent/                  # FastAPI service that runs LOCALLY on the officer's machine
│   ├── pqc_agent.py              # Key generation, device-proof signing, sign+encrypt, decrypt
│   ├── pqc_private_keys.enc      # Officer's own encrypted private key store
│   └── oqs.dll
│
├── docs/                        # Architecture decision records / reviewer responses
│   ├── CA_TSA_BOUNDARY.md
│   ├── OFFICER_DEVICE_AUTH.md
│   ├── PORTAL_BOUNDARIES.md
│   ├── REVIEWER_RESPONSE.md
│   └── STORAGE_MODEL.md
│
├── deployment/
│   ├── apache-postquantum-tls13.conf.example   # Apache TLS 1.3 reverse-proxy config
│   └── start-local-demo.ps1                     # One-shot script to launch all 4 services + Apache
│
├── requirements.txt             # Shared Python dependencies for all services
├── .env.example                 # Example environment configuration
├── .gitignore
└── PostQuantum.sln              # Visual Studio solution grouping the Python projects
```

---

## Services in Detail

### 1. PublicAdminWeb — Django Portal

The only service exposed to the public internet (`https://thanhthuydepgai.42web.io` in the demo config, behind an Apache TLS 1.3 reverse proxy to `127.0.0.1:8000`).

**Roles supported:** `citizen`, `officer`, `admin` — stored per-user in MongoDB (`db.users`), not Django's built-in auth system. Passwords are hashed with **Argon2** (`argon2-cffi`).

**Key routes** (`PublicAdminWeb/urls.py`):

| Route | Purpose |
|---|---|
| `/register/`, `/login/`, `/logout/` | Account creation & session-based auth |
| `/upload/` | Citizens upload a PDF and pick a receiving officer |
| `/dashboard/` | Role-aware view of applications (citizen/officer/admin see different subsets) |
| `/ra/requests/`, `/ra/requests/<id>/approve|reject/` | Admin review queue for officer certificate requests (proxies to RA Server) |
| `/sign/<doc_id>/` | Officer signs a document (via the local PQC Agent) |
| `/decrypt/<doc_id>/` | Officer decrypts an assigned application locally |
| `/verify/` | Anyone can upload a signed PDF to verify its ML-DSA signature, hash, TSA timestamp, and certificate status |
| `/media/download/signed/<doc_id>/` | Download a completed signed PDF |
| `/api/ca-public-key/`, `/api/ca-tsa/` | Thin proxies so the browser-side PQC Local Agent can reach the CA without CORS issues |
| `/api/device-challenge/`, `/api/device-verify/` | Officer device-possession challenge/response (see [Officer Device Auth](#officer-device-authentication)) |

The portal itself never touches an officer's or citizen's private key — it only relays ciphertext and calls out to the CA/RA services and to the officer's local Agent.

### 2. CA-TSA Server — Certificate Authority & Timestamping Authority

FastAPI service on port **5001**, restricted to loopback callers only (`ip_whitelist_middleware` rejects anything not from `127.0.0.1`/`::1`).

Responsibilities (per `docs/CA_TSA_BOUNDARY.md`):
- Generates and stores its own master **ML-KEM-1024** (transport encryption) and **ML-DSA-65** (certificate signing) keypairs, encrypted at rest in `ca_hsm_secured.json` (a JSON file simulating a PKCS#11/HSM-wrapped key store, AES-GCM wrapped).
- `POST /issue-officer-certificate` — issues an X.509-like JSON certificate for an officer after receiving an RA-approved request (ML-KEM-1024-encrypted service-to-service payload).
- `POST /encrypt-pdf` — encrypts a citizen's freshly uploaded PDF in-memory with **ML-KEM-768**, writes ciphertext to private blob storage, and records only metadata in MongoDB.
- `POST /verify-and-store-signed` — runs a 4-layer verification when an officer submits a signed document: (1) decrypt the in-transit payload, (2) verify the officer certificate's CA signature (tamper detection), (3) check certificate validity/expiry, (4) verify the ML-DSA-65 signature over the document hash.
- `POST /tsa/timestamp` — issues a signed (ML-DSA-65) timestamp token over a document hash.
- `POST /api/v1/ocsp`, `GET /api/v1/crl` — certificate status / revocation list, both signed by the CA key.
- `GET /master-public-key` — exposes only the CA's **transport** public key (explicitly marked `"key_purpose": "ca-transport-only"`).
- `POST /decrypt-pdf` — intentionally returns **HTTP 410 Gone**: the CA is explicitly forbidden from decrypting user documents. This is a deliberate design fix, not a missing feature (see [Trust Boundaries](#trust-boundaries--security-design)).

### 3. RA Server — Registration Authority

FastAPI service on port **5002**. Split out from the CA/TSA server specifically so certificate *issuance authority* and *approval/review workflow* are separate concerns (`docs/CA_TSA_BOUNDARY.md`).

- `POST /certificate-requests` — an officer's registration submits a CSR-like request (username, subject DN, ML-DSA/ML-KEM public keys) and stores it as `pending` in MongoDB.
- `GET /certificate-requests?status=pending` — lists requests for the admin review queue.
- `POST /certificate-requests/{id}/approve` — only after an admin approves does the RA Server call the CA/TSA's `/issue-officer-certificate` endpoint (transport-encrypted with ML-KEM-1024) and activate the officer's account.
- `POST /certificate-requests/{id}/reject` — marks the officer's account inactive with a review note.

### 4. PQC Local Agent — `pqc_agent.py`

FastAPI service on port **54321**, designed to run **on the officer's own workstation**, not on the server. This is the only component that ever holds an officer's private keys.

- `POST /api/generate-keys` — generates an officer's **ML-DSA-65** (signing) and **ML-KEM-768** (decryption) keypairs locally, encrypts the private halves with a passphrase-derived key (**PBKDF2-HMAC-SHA256**, 100,000 iterations) and AES-GCM, and writes them to `pqc_private_keys.enc`. Only the public keys are sent to the server for certificate registration.
- `POST /api/device-proof` — decrypts the local key store with the officer's passphrase and signs a server-issued random challenge with ML-DSA-65, proving possession of the private key without ever exposing it.
- `POST /api/sign-and-encrypt` — the core signing flow: hashes the PDF (SHAKE-256), signs the hash with ML-DSA-65, fetches a TSA timestamp token, embeds the signature/timestamp/certificate metadata into the PDF (a PAdES-like structure via `pikepdf`), then re-encrypts the whole signed PDF to the CA's ML-KEM-1024 transport key for delivery.
- `POST /api/decrypt-pdf` — decapsulates an ML-KEM-768 ciphertext with the officer's local private key and returns the plaintext PDF, entirely on the officer's machine.
- CORS is restricted via `AGENT_ALLOWED_ORIGIN_REGEX` so only the configured portal origin (localhost or the public demo domain) can call it from a browser.

---

## Cryptography

All post-quantum primitives come from **[liboqs](https://github.com/open-quantum-safe/liboqs)** via the `liboqs-python` binding (`import oqs`), backed by the native `oqs.dll` shipped alongside each service (Windows).

| Purpose | Algorithm | Where used |
|---|---|---|
| Key encapsulation (document encryption, service-to-service transport) | **ML-KEM-768** (citizen documents) / **ML-KEM-1024** (CA master/transport key) | `encrypt-pdf`, `sign-and-encrypt`, CA↔RA transport |
| Digital signatures (officer signing, CA certificate signing, TSA, OCSP/CRL) | **ML-DSA-65** | All signing operations |
| Symmetric encryption | **AES-256-GCM**, keyed by the ML-KEM shared secret | Wrapping every KEM-derived session |
| Document hashing | **SHAKE-256** (32-byte digest, output of SHA-3's XOF) | PDF content hashing, certificate/response hashing |
| Local key-store password hashing/derivation | **PBKDF2-HMAC-SHA256** (Local Agent) / **Argon2** (Django user passwords) | Passphrase-protecting officer private keys / user login |

ML-KEM (Kyber) and ML-DSA (Dilithium) are the NIST FIPS 203 and FIPS 204 standardized post-quantum algorithms — hence the project name.

---

## Core Workflows

**1. Officer onboarding**
`Register (portal) → generate ML-DSA/ML-KEM keys locally (PQC Agent) → CSR sent to RA Server → admin reviews in /ra/requests/ → RA calls CA to issue certificate → officer account activated.`

**2. Citizen document submission**
`Citizen uploads PDF + picks officer → Django sends PDF to CA/TSA /encrypt-pdf → CA encrypts with ML-KEM-768 to the officer's public key → ciphertext written to private blob storage, metadata-only record in MongoDB.`

**3. Officer decrypt & review**
`Officer opens /decrypt/<doc_id>/ → ciphertext fetched from blob storage → decryption happens in the browser calling the officer's own PQC Local Agent (ML-KEM-768 decapsulation with the local private key) → plaintext never touches the server.`

**4. Officer signing**
`Officer device-proof challenge (/api/device-challenge/ → Agent signs with ML-DSA-65 → /api/device-verify/) → PQC Agent hashes + signs the PDF, fetches a TSA timestamp, embeds everything into the PDF, and encrypts the result to the CA's ML-KEM-1024 key → Django forwards to CA's /verify-and-store-signed for 4-layer verification → signed PDF stored in the portal's delivery folder for citizen download.`

**5. Signature verification (public)**
`Anyone uploads a signed PDF to /verify/ → SHAKE-256 hash recomputed → embedded ML-DSA-65 signature checked against the officer's certificate public key → OCSP status checked → TSA timestamp/document hash cross-checked.`

### Officer Device Authentication

Rather than trusting an office IP address, the officer's authorization is proven cryptographically: the portal issues a random `/api/device-challenge/`, the browser relays it to the local PQC Agent, the Agent signs it with the officer's ML-DSA-65 private key (after passphrase-unlocking the local key store), and the portal verifies that signature against the certificate on file before allowing a signing or local-decrypt action (`docs/OFFICER_DEVICE_AUTH.md`).

---

## Data & Storage Model

Per `docs/STORAGE_MODEL.md`, MongoDB Atlas is treated strictly as **metadata storage**, never as a blob store for document content:

- **Stored in MongoDB:** user/officer/citizen records, certificate records, CSR review state, KEM ciphertext *metadata* (encapsulated key, nonce, algorithm, hash, size, blob reference), and audit logs.
- **Stored outside MongoDB:** actual encrypted PDF bytes (in `PRIVATE_BLOB_STORAGE_ROOT`, path-sanitized against traversal), and finished signed PDFs delivered to citizens (in the Django `media/signed_results` folder).
- MongoDB documents only ever reference blobs via `blob_ref` + `ciphertext_sha256` + `ciphertext_size_bytes`, so a database leak alone does not leak document contents.

---

## Trust Boundaries & Security Design

The `docs/` folder is effectively a set of architecture decision records written in response to a security review; each doc maps a specific reviewer concern to a corresponding code fix (see `docs/REVIEWER_RESPONSE.md` for the full table with git branch/commit references):

1. **Public citizen portal, not an intranet app** — the portal is reachable over the public internet via TLS 1.3, not hidden behind an internal-only network (`PORTAL_BOUNDARIES.md`).
2. **Real TLS 1.3 domain demo** instead of presenting everything as `127.0.0.1` (`apache-postquantum-tls13.conf.example`, hosts-file mapping for the local demo).
3. **Configurable service URLs** — no hardcoded `localhost`; every inter-service URL comes from environment variables.
4. **Metadata-only cloud database** — document ciphertext lives in private blob storage, not MongoDB, addressing the risk of a DB leak exposing document content.
5. **CA/TSA has no document-key role** — the CA issues certificates, timestamps, and verifies signatures, but explicitly cannot decrypt user documents or manage document encryption keys (`/decrypt-pdf` returns `410 Gone`).
6. **Officer device authentication** replaces office-IP-based trust with cryptographic proof of private-key possession.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Web portal | Django ≥ 5.0 |
| Internal services | FastAPI ≥ 0.110 + Uvicorn |
| Post-quantum crypto | `liboqs-python` (ML-KEM, ML-DSA) via `oqs.dll` |
| Classical crypto | `cryptography` (AES-GCM, PBKDF2) |
| Password hashing | `argon2-cffi` |
| PDF manipulation | `pikepdf`, `lxml`, `Pillow` |
| Database | MongoDB Atlas (`pymongo`, `dnspython`) — metadata only |
| Reverse proxy / TLS | Apache with TLS 1.3, ZeroSSL ECDSA certificate (demo) |
| Frontend | Server-rendered Django templates, Bootstrap 3, jQuery |
| Testing | `pytest` |

---

## Setup & Running Locally

### Prerequisites
- Python (with a virtual environment — the repo's own dev venv targets Python 3.14)
- `liboqs` native library (`oqs.dll` is bundled for Windows; other platforms need a native `liboqs` build)
- MongoDB Atlas connection string (or a compatible MongoDB instance)
- Windows + Apache 2.4 if reproducing the full TLS 1.3 reverse-proxy demo (`deployment/start-local-demo.ps1` is Windows/PowerShell-specific)

### Install dependencies
```bash
pip install -r requirements.txt
```

### Configure environment
Copy `.env.example` to `.env` and fill in real values — in particular replace `DJANGO_SECRET_KEY` and the MongoDB URI before any non-local deployment (see [Known Demo Limitations](#known-demo-limitations)).

### Run the services (each in its own terminal)
```bash
# 1. CA/TSA service
cd "CA-TSA Server" && python main.py          # http://127.0.0.1:5001

# 2. Registration Authority
cd "RA Server" && python main.py               # http://127.0.0.1:5002

# 3. PQC Local Agent (run this on each officer's own machine)
cd pqc_agent && python pqc_agent.py             # http://127.0.0.1:54321

# 4. Django portal
cd PublicAdminWeb
python manage.py seed_demo_admin                # creates a demo admin account
python manage.py runserver 127.0.0.1:8000
```

### One-shot local demo (Windows)
`deployment/start-local-demo.ps1` automates the above: it seeds the demo admin, starts all three backend services (checking ports first so it won't double-start them), starts the Django portal, and finally starts Apache as a TLS 1.3 reverse proxy — reproducing the full "public HTTPS domain, backed by localhost services" demo topology.

---

## Configuration (Environment Variables)

From `.env.example` / `PublicAdminWeb/settings.py`:

| Variable | Purpose |
|---|---|
| `PUBLIC_PORTAL_DOMAIN` / `PUBLIC_PORTAL_ORIGIN` | The public-facing hostname/origin of the Django portal |
| `DJANGO_ALLOWED_HOSTS` / `DJANGO_CSRF_TRUSTED_ORIGINS` | Standard Django host/CSRF allow-lists |
| `DJANGO_DEBUG` | Debug mode toggle (should be `false` outside local demos) |
| `DJANGO_SECRET_KEY` | Django secret key — **must** be replaced before any public deployment |
| `DJANGO_SESSION_COOKIE_SECURE` / `DJANGO_CSRF_COOKIE_SECURE` / `DJANGO_SECURE_SSL_REDIRECT` | Cookie/redirect hardening flags, expected `true` behind real TLS |
| `CA_SERVICE_URL` | Where Django/RA reach the CA/TSA FastAPI service (default `http://127.0.0.1:5001`) |
| `RA_SERVICE_URL` | Where Django reaches the RA FastAPI service (implied default `http://127.0.0.1:5002`) |
| `LOCAL_AGENT_URL` | Where the browser reaches the officer's PQC Local Agent (default `http://127.0.0.1:54321`) |
| `AGENT_ALLOWED_ORIGIN_REGEX` | CORS allow-list regex for the Local Agent |
| `OFFICER_DEVICE_PROOF_TTL_SECONDS` | How long a device-proof stays valid before re-verification is required (default 900s) |
| `MONGO_URI` / `MONGO_DATABASE` | MongoDB Atlas connection details |
| `PRIVATE_BLOB_STORAGE_ROOT` | Filesystem root for encrypted document blobs (kept out of MongoDB) |

> **Security note:** `PublicAdminWeb/app/db_connection.py`, `CA-TSA Server/db_connection.py`, and `RA Server/db_connection.py` currently contain a **hardcoded MongoDB Atlas URI and password** rather than reading `MONGO_URI` from the environment, and `settings.py` ships a fallback `DJANGO_SECRET_KEY`. Both should be moved to environment variables (as `.env.example` already anticipates) and rotated before any deployment outside the local demo.

---

## Known Demo Limitations

The docs are explicit that several pieces are simplified for a local course/defense demo rather than production-hardened:

- The CA's master keys are protected by a **simulated HSM** (an AES-GCM-wrapped JSON file with a hardcoded wrapping key derived from a fixed string), not a real hardware security module.
- The officer's local private key store is protected only by a passphrase-derived AES key on disk, not by hardware-backed secure storage (TPM/HSM/secure enclave) — `docs/OFFICER_DEVICE_AUTH.md` calls this out explicitly as a "software local-agent proof suitable for a course demo."
- The public TLS 1.3 domain (`thanhthuydepgai.42web.io`) is mapped to `127.0.0.1` via the local hosts file rather than pointing at a real public server — it demonstrates the certificate/SNI/TLS 1.3/reverse-proxy pattern without needing a public VM.
- `deployment/start-local-demo.ps1` is Windows/PowerShell + Apache-for-Windows specific.
- CA-issued "certificates" are custom JSON documents signed with ML-DSA-65, not standard X.509 (no PQC-signed X.509 profile is widely deployed yet), so they won't interoperate with off-the-shelf PKI tooling.

---

## Project History

The git history shows this evolved from an initial working PDF-encrypt/sign/decrypt/verify flow into a formally reviewed PKI architecture, with each fix tied to a specific reviewer concern (see commit messages like `fix: separate public citizen portal from internal officer access`, `fix: limit ca server to certificate tsa and revocation duties`, `fix: require officer device challenge instead of office ip`, and the corresponding `docs/*.md` write-ups). `docs/REVIEWER_RESPONSE.md` is the single best entry point for understanding *why* the architecture is shaped the way it is.
