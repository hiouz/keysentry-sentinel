# KeySentry — NEAR account-change guard

[![verify](https://github.com/hiouz/keysentry-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/hiouz/keysentry-sentinel/actions/workflows/ci.yml)

KeySentry is a NEAR testnet security guard. Its public scanner performs a one-time check of public account access keys and deployed-code hashes without saving the account ID or result. It never requests a seed phrase or private key. The optional Testnet Signing Lab opens MyNearWallet only after an explicit click.

## Run locally

```sh
npm ci
npm run build
npm test
npm run check
npm run release:verify
npm start
```

Open `http://127.0.0.1:4174`. Public mode sends an entered account ID only to the configured public RPC for the current response; it does not save the ID, scan, alert, or audit record. Refreshing or reopening the page clears the input and displayed result. The default RPC is `https://rpc.testnet.near.org`; set `NEAR_RPC_URL` to use a different compatible endpoint.

## What is implemented

- One-time private checks: no server-side watch, alert, audit record, or account-ID persistence.
- Public RPC scans of access keys, account height, and deployed-code hash.
- A deterministic preflight endpoint for action-preview JSON. Per-account policy blocks full-access-key additions and code deployment by default; unknown or malformed actions fail closed.
- A permission attack-path model that maps each public key to its visible receiver/method surface, flags changed code semantics, and states its proof boundary explicitly.
- A Signature Guard SDK and `/api/decisions` endpoint that assess fresh public state before a consuming wallet or dApp signing callback runs. The SDK stops `BLOCK` and requires an explicit approval callback for `REVIEW`; it never receives a private key.
- Optional Testnet Signing Lab: tests the real decision-to-wallet boundary. A full-access-key sample is blocked before wallet invocation; a 1 yoctoNEAR self-transfer requires both KeySentry review and a final wallet confirmation.
- Persistent monitoring remains disabled by default. It may only be enabled in an authenticated private deployment with `KEYSENTRY_ENABLE_PERSISTENT_MONITORING=true`; do not enable it on the public demo.
- Unit tests for the preflight rules and change-detection engine.

## API for testing

```sh
curl http://127.0.0.1:4174/api/health
curl -X POST http://127.0.0.1:4174/api/check -H 'content-type: application/json' -d '{"accountId":"guest-book.testnet"}'
```

## Honest boundary

This is not a smart-contract audit, malware detector, phishing guarantee, or exploit predictor. It does not prove a contract safe; it reports exactly the public state inspected and gives the user a safer investigation path. The optional wallet lab asks the selected wallet to sign only after the preflight result and explicit user confirmation; KeySentry never receives a seed phrase or private key. The app's selector state is in memory, but an external wallet may maintain its own session under its own rules. Production monitoring needs authenticated operators, encrypted durable storage, notification delivery, rate-limit/retry telemetry, and an independently reviewed wallet integration.

## Build, test, and team handoff

Run `npm run build`, `npm test`, `npm run check`, and `npm run release:verify` before every handoff. A container build is provided for a clean, reproducible demo: `docker build -t keysentry-sentinel .` followed by `docker run --rm -p 4174:4174 keysentry-sentinel`. The image intentionally excludes `data/`, so no local monitoring history is distributed. See [SUBMISSION.md](./SUBMISSION.md) for the demo script and [SUBMIT.md](./SUBMIT.md) for the exact form copy and final checklist.
