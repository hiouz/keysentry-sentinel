# KeySentry Sentinel — Team Submission Pack

## One-line pitch

KeySentry Sentinel is a read-only NEAR account security guard that turns public access-key permissions, contract-code drift, and transaction previews into evidence-backed attack paths before damage occurs.

## What is genuinely implemented

- Live NEAR testnet RPC scan: access keys, final block height, and deployed-code hash.
- Privacy-first one-time checks: account IDs and results are not saved in public mode.
- Permission Attack-Path Model: maps each visible key to its receiver/method surface and explicitly marks what it cannot prove.
- Deterministic preflight that fails closed for unknown actions and blocks high-risk account operations by policy.
- Signature Guard SDK: a dApp or wallet calls the decision API before its signing callback; `BLOCK` never reaches that callback and `REVIEW` requires an explicit approval callback.
- Optional Testnet Signing Lab: connects a user-selected testnet wallet only after a click, blocks a full-access-key action before the wallet is invoked, and offers a 1 yoctoNEAR self-transfer only after review.
- Persistent monitoring is deliberately disabled in the public demo and reserved for a future authenticated private workspace.

## Three-minute judge demo

1. Open the app, paste `guest-book.testnet`, and scan it (public testnet data). Refresh afterward to show that the input and result reset completely.
2. Point to the Permission Attack-Path Model: it shows full-account-control paths separately from bounded function-key paths.
3. Use **Simulate key drift**. State clearly that this is an in-browser labelled simulation and never changes or stores a NEAR account.
4. Use **Check before signing** with the Transaction Preflight sample. It requests a fresh public-state decision and shows a decision ID, block height, and the exact point where the SDK stops a wallet callback.
5. Run **Full-access block demo**: it returns `BLOCK` and explicitly says no wallet was invoked. If a testnet wallet is available, connect it and demonstrate the 1 yoctoNEAR self-transfer; approve it only in the wallet after KeySentry's review. Otherwise, show `sdk/keysentry.mjs`: `protectSignature` prevents a wallet signing callback from being invoked for `BLOCK` and requires explicit review for `REVIEW`.

## Honest boundaries

This product does not request, store, sign with, or transmit a seed phrase, private key, wallet address book, or personal identity data. In public one-time-check mode, an entered account ID is sent to public NEAR RPC only for the current result and is not written to KeySentry storage, audit records, alerts, or watchlists. The optional wallet lab maintains KeySentry selector state only in memory; a selected external wallet can maintain a separate wallet session. It does not prove a contract exploit, identify a key owner, predict every future attack, block an on-chain transaction, or replace a contract audit.

## Reproducible test commands

```sh
npm test
npm run check
npm run build
npm run release:verify
docker build -t keysentry-sentinel .
docker run --rm -p 4174:4174 keysentry-sentinel
curl http://127.0.0.1:4174/api/health
```

Open `http://127.0.0.1:4174`. The container starts with an empty `/data` volume, so no local scan history is bundled.

## Submission fields to prepare

- Project name: **KeySentry Sentinel**
- Category: security infrastructure / developer tooling
- Demo URL: deploy the container and provide its HTTPS URL
- Repository URL: push this directory without `data/`, `build/`, or `contract/`
- Demo video: use the three-minute flow above
- Technical description: use the one-line pitch and implementation list above
- Privacy disclosure: use the Honest boundaries paragraph above

Before the final submission click, confirm the hackathon's current form fields, deadline, team-member eligibility, and any required public repository or video link on the organizer's official page.
