# verifiable-reviewer

A Tinfoil-attested container that reviews a release diff with an LLM and publishes a signed attestation of the review to Sigstore/Rekor.

## Why

Prove _this exact diff was reviewed by this exact prompt, and this is what it concluded._ Anyone can later verify the claim from the Rekor entry without trusting Tinfoil.

## API

`POST /review` (bearer auth: `REVIEWER_API_KEY`)

```json
{
  "repo": "tinfoilsh/cvmimage",
  "prev_tag": "v0.4.1",
  "current_tag": "v0.4.2"
}
```

The reviewer fetches `https://github.com/<repo>/compare/<prev_tag>...<current_tag>.diff` itself and hashes those bytes as the in-toto subject. The caller never supplies the diff, so the attestation can't be tricked into signing over bytes that don't match the named commit range — a verifier re-fetching the same URL gets the same bytes and re-derives the same hash.

Response: `{"rekor_url": "..."}` — the Rekor entry URL. `200` means the review was signed and published; `502` means Rekor publication failed (nothing is returned to the caller).

## What the attestation actually claims

The signed in-toto Statement (`predicateType: https://tinfoil.sh/predicate/code-review/v1`) contains:

- `subject.digest.sha256` — sha256 of the diff bytes the TEE fetched (verifiers re-fetch the same `compare/<a>...<b>.diff` URL and confirm the hash matches)
- `predicate.repo` / `prev_tag` / `current_tag` / `diff_sha256` — the reviewed range and its hash (mirrors `subject.digest`)
- `predicate.diff_bytes` — raw byte length of the fetched diff
- `predicate.truncated` / `predicate.omitted_files` — true when the diff exceeded the LLM packing budget and some files were dropped from the model's input
- `predicate.review_text` / `malicious` / `malicious_reasoning` — LLM judgment
- `predicate.model` — model name
- `predicate.ts` — UTC timestamp of the review
- `predicate.cert_sha256` — sha256 fingerprint of the enclave's TLS cert. The cert is the durable home of the hardware attestation hash: at boot the enclave's attestation document hash (`sha256(format + body)`) is dcode-encoded into the cert's `.hatt.` SAN extension, the cert is issued by a public CA, and the issuance is logged in CT. The fingerprint here is how a verifier locates the right CT entry.

The DSSE signature is made with that same per-boot TLS key. To verify a published entry:

1. Fetch the Rekor entry (an `intoto` v0.0.1 entry). `spec.publicKey` carries the bare SPKI pubkey; `spec.content.envelope` is the DSSE envelope with the in-toto Statement as its base64 `payload`. The decoded Statement is also returned inline as `attestation.data` on GET.
2. Look the leaf cert up in CT by `predicate.cert_sha256` (e.g., `crt.sh/?q=<cert_sha256>`). Confirm its pubkey matches the Rekor verifier.
3. Verify the DSSE signature against that pubkey.
4. Decode the `.hatt.` hash from the cert's SAN extension. Search Rekor for a second entry with `subject.digest.sha256 = cert_sha256` and `predicateType = https://tinfoil.sh/predicate/enclave-attestation/v1` — this is the boot attestation entry. Verify its DSSE signature (same key), then confirm `predicate.attestation_hash` matches the `.hatt.` hash from the cert.
5. Parse `predicate.attestation` (a `verifier.Document{Format, Body}`), verify the VCEK signature on the SEV-SNP report, and compare the hardware measurement against the published `verifiable-reviewer` image measurement (the Sigstore bundle from `measure-image-action`).
6. Confirm `sha256(cert.PublicKey) == report_data.tls_key_fp`.

Steps 3 + 6 prove the signature came from a key that lived inside the measured enclave. Step 5 proves the measured enclave is running this repo's code. Step 2 anchors the cert in CT — independent of Rekor. Step 4 retrieves the historical attestation document (published once per boot) so verification doesn't require a live enclave.

## Boot attestation entry

At startup, the reviewer publishes a second Rekor entry containing the enclave's full attestation document. This entry is keyed by `subject.digest.sha256 = cert_sha256` and uses `predicateType: https://tinfoil.sh/predicate/enclave-attestation/v1`. The predicate carries:

- `cert_sha256` — the enclave cert fingerprint (same value as in review entries)
- `attestation_hash` — `sha256(format + body)` of the attestation document, matching the `.hatt.` hash in the cert's SAN
- `attestation` — the full attestation document (`verifier.Document{Format, Body}`)

This entry is published once per boot (a flag file in the tmpfs state dir prevents re-publishing on container restart within the same boot). It allows verifiers to retrieve the historical attestation document without a live enclave, completing the trust chain from CT cert → attestation document → hardware measurement.

## Operational notes

- TLS key + matching cert are bind-mounted at `/tinfoil-app/tls.key` and `/tinfoil-app/tls.crt` via `tinfoil-config.yml`'s `volumes` (mode 0600 key, run as root). The cert is hashed once at startup; the hash goes into every envelope's `predicate.cert_sha256`.
- The attestation document is read from `/tinfoil/attestation.json` (the CVM's public ramdisk, mounted read-only). A tmpfs mount at `/var/lib/verifiable-reviewer` holds the flag file that prevents duplicate attestation entries.
- Outbound network: `inference.tinfoil.sh` (LLM, verified via the Tinfoil SDK — the SDK fetches the inference enclave's Sigstore bundle and verifies its attestation before sending the prompt), `rekor.sigstore.dev` (publishing), and `github.com` + `codeload.github.com` (diff fetch — the compare URL 302s from the former to the latter). The SDK also reaches `github.com` and Sigstore for the inference enclave's code measurement.

## Configuration

Required environment (injected as Tinfoil secrets):

- `TINFOIL_API_KEY` — outbound auth to Tinfoil inference
- `REVIEWER_API_KEY` — inbound auth on `/review`

Optional:

- `LLM_MODEL` (default `gpt-oss-120b`)
- `REKOR_URL` (default `https://rekor.sigstore.dev`)
