# Officer Device Authentication

Officer access is not tied to an office IP address. The system verifies the officer device by proving possession of the local ML-DSA private key.

## Flow

1. The officer logs in with a normal account session.
2. For signing or local decrypt actions, the portal calls `/api/device-challenge/`.
3. The browser sends that challenge to the PQC Local Agent.
4. The Local Agent decrypts the local private-key store with the officer passphrase and signs the challenge using ML-DSA-65.
5. The portal calls `/api/device-verify/` and verifies the signature with the officer public key registered in the CA-issued certificate record.
6. The portal stores a short-lived `officer_device_verified_at` session timestamp.

## Why This Fixes the Review Concern

Digital signing is supposed to work from an authorized device, not only from a government office LAN. The officer's private key remains on the local machine and never goes to Django, MongoDB, or the CA/RA/TSA service.

## Demo Scope

This is a software local-agent proof suitable for a course demo. A production version would bind the private key to hardware-backed secure storage or an HSM-backed token and would add device inventory, revocation, and monitoring.
