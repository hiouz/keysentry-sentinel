# KeySentry Sentinel — final submission checklist

## Paste into the NEAR Hackathon form

- **Project name:** KeySentry Sentinel
- **Track:** AI Security & Defense
- **Website:** `<PUBLIC_HTTPS_DEMO_URL>`
- **Repository link:** `<PUBLIC_GITHUB_REPOSITORY_URL>`
- **Demo post link:** `<PUBLIC_X_POST_URL>`

### What did you build?

KeySentry Sentinel is a privacy-first NEAR security guard for autonomous agents and wallets. It reads the current public access-key permissions and contract-code hash from NEAR testnet, then turns each key into an evidence-backed permission attack path. Before a wallet or dApp signs an action, KeySentry applies deterministic, fail-closed policy: full-access-key creation and contract deployment are blocked; key removal and asset transfers require explicit review; unknown or malformed actions never receive a silent allow. The public demo stores no entered account ID, scan result, decision, alert, or watchlist. Its optional Testnet Signing Lab proves the boundary: a full-access-key request is blocked before wallet invocation, while a harmless 1 yoctoNEAR self-transfer requires both KeySentry review and final wallet approval. KeySentry does not request seed phrases or private keys, and it clearly labels limits: it is not a contract audit or a guarantee that a receiver contract is safe.

## Before the final click

- [ ] Replace every `<...>` placeholder above.
- [ ] Enter your own **testnet or main NEAR prize wallet address** in the official form; it is only the prize destination, not a connection request.
- [ ] Push this repository to GitHub and set it **Public**.
- [ ] Deploy the Docker image to stable HTTPS hosting. Do not use a temporary quick-tunnel URL for the final form.
- [ ] Post the demo video or screenshots on X, including `@NEARProtocol` and `#NEARHackathon`.
- [ ] Attach the public GitHub and X-post links to the official form.
- [ ] Confirm the description still matches the running demo and do not claim an on-chain transfer unless it was actually approved in a testnet wallet.

## Demonstration order

1. Scan `guest-book.testnet`.
2. Show the permission attack-path model and the public-RPC evidence.
3. Refresh the page to prove the entered ID and result are cleared.
4. Run the full-access-key block demo; say clearly that the wallet was not called.
5. Optionally connect a dedicated testnet wallet and approve the 1 yoctoNEAR self-transfer only after checking its recipient in the wallet.
