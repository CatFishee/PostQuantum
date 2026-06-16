# Public Portal and Internal Trust Boundaries

This demo uses one Django web portal that is reachable by citizens over HTTPS:

- Public host: `https://thanhthuydepgai.42web.io`
- TLS boundary: Apache terminates TLS 1.3 with the public certificate, then reverse-proxies to Django on `127.0.0.1:8000`.
- Citizen-facing routes: registration, login, document upload, dashboard, signed-document verification.
- Officer-facing routes: dashboard, document signing, local decrypt workflow.

The portal is not described as an intranet-only website. Citizens can submit documents through the HTTPS domain. Internal-only components are the service-to-service links behind the portal:

- Django to CA/RA/TSA service through `CA_SERVICE_URL`.
- Browser to PQC Local Agent through `LOCAL_AGENT_URL`.
- CA/RA/TSA service to MongoDB Atlas for metadata and audit records.

## Reviewer Concern

If the web portal is only internal and not on the internet, citizens cannot upload documents.

## Corrected Design

The citizen portal is public and protected by TLS 1.3. Citizens upload PDF submissions through the portal. The portal then calls backend services from the server side. Officer operations are separated by role and device-backed signing flows, not by hiding the entire portal from the internet.

## Demo Scope

For a local defense demo, the hosts file maps `thanhthuydepgai.42web.io` to `127.0.0.1`, so the browser still shows the public domain while traffic stays on the laptop. This demonstrates certificate validation, SNI, TLS 1.3, and reverse-proxy deployment without requiring a public VM.
