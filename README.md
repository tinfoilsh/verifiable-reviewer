# verifiable-reviewer

A Tinfoil-attested container that reviews a release diff with an LLM and publishes a signed attestation of the review to Sigstore/Rekor.

## Why

A reviewer running outside a TEE produces an opinion. A reviewer running inside one produces a cryptographic claim: *this exact diff was reviewed by this exact code, and this is what it concluded.* Anyone can later verify the claim from the Rekor entry without trusting Tinfoil.

## API

`POST /review` (bearer auth: `REVIEWER_API_KEY`)

```json
{
  "repo": "tinfoilsh/cvmimage",
  "prev_tag": "v0.4.1",
  "latest_tag": "v0.4.2",
  "diff": "<unified diff text>",
  "files": [{"path": "...", "patch": "..."}]
}
```

`diff` is hashed as the in-toto subject; `files` is the LLM input. Callers should derive both from the same source — re-deriving the hash later proves the attestation covered the same bytes.

Response: a DSSE envelope + Rekor coordinates (`log_index`, `uuid`, fetch URL). A `202` instead of `200` means the envelope is signed but Rekor publication failed; the envelope can be retried out of band.

## What the attestation actually claims

The signed in-toto Statement (`predicateType: https://tinfoil.sh/predicate/code-review/v1`) contains:

- `subject.digest.sha256` — hash of the diff bytes
- `predicate.review_text` / `malicious` / `malicious_reasoning` — LLM judgment
- `predicate.model` — model name
- `predicate.tinfoil_attestation` — the full boot-time hardware attestation document

The DSSE signature is made with the per-boot TLS key, whose fingerprint is bound into the attestation report's `report_data.tls_key_fp`. To verify a published entry:

1. Fetch the DSSE envelope from Rekor.
2. Verify the signature against the cert/key in `predicate.tinfoil_attestation.certificate`.
3. Verify the embedded attestation report's hardware measurements against the expected `verifiable-reviewer` image measurement (published by `measure-image-action` at release time).
4. Confirm `sha256(cert.PublicKey) == report_data.tls_key_fp`.

Steps 2 + 4 prove the signature came from a key that lived inside the measured enclave. Step 3 proves the measured enclave is running this repo's code.

## Operational notes

- TLS key is bind-mounted at `/tinfoil/tls.key` because `tinfoil-config.yml` sets `enable-app-signing: true`. Container compromise leaks the key — opt-in is intentional.
- Boot-time attestation document is read once at startup from `/tinfoil/attestation.json` and embedded verbatim in every signed envelope. No per-request shim round-trip.
- Outbound network: `inference.tinfoil.sh` (LLM) and `rekor.sigstore.dev` (publishing).

## Configuration

Required environment (injected as Tinfoil secrets):

- `TINFOIL_API_KEY` — outbound auth to Tinfoil inference
- `REVIEWER_API_KEY` — inbound auth on `/review`

Optional:

- `LLM_URL` (default `https://inference.tinfoil.sh/v1/chat/completions`)
- `LLM_MODEL` (default `gpt-oss-120b`)
- `REKOR_URL` (default `https://rekor.sigstore.dev`)
- `LISTEN_ADDR` (default `:8080`)
