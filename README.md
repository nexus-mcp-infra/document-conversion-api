# Document Conversion API

Converts between PDF/Office documents and structured JSON, both directions. NEXUS candidate #6 --
**manual build, not FORGE-generated**, following the same manual-Cloud-Run-asset pattern as candidate #3
(`agent-verification-api`) and candidate #4 (`url-metadata-api`).

- `POST /extract-pdf-to-json` -- text, tables (per page), page count, metadata. **$0.02/call.**
- `POST /extract-docx-to-json` -- paragraphs (with heading levels/styles), tables, metadata. **$0.01/call.**
- `POST /extract-xlsx-to-json` -- per-sheet cell grids, capped rows/cols. **$0.01/call.**
- `POST /generate-pdf-from-json` -- structured blocks (heading/paragraph/table) -> PDF bytes. **$0.02/call.**
- `POST /generate-docx-from-json` -- structured blocks -> .docx bytes. **$0.01/call.**
- MCP tools at `/mcp` mirroring all 5 -- **currently free**, see "Known limitations".
- `GET /health`, `GET /.well-known/agent-card.json`, `GET /openapi.json` (has `x-payment-info`).

All 5 endpoints take **base64-encoded file bytes directly in the request body** -- never a URL to fetch.
This is a deliberate scope boundary: it removes SSRF from this asset's risk surface entirely (unlike
`url-metadata-api`/`agent-verification-api`, which both fetch caller-supplied URLs and need SSRF guards).

## Why these libraries, why no external data source

Pure OSS, mature, no LLM calls, **zero external network calls at runtime** (fully local computation):
`pdfplumber` (PDF extraction, wraps `pdfminer.six`), `python-docx` (Word), `openpyxl` (Excel),
`reportlab` (PDF generation). No named third-party data source anywhere in this asset -- deliberately,
to avoid the BuyWhere-style hallucination risk (`skills/asset-lifecycle`): there is nothing external to
get wrong, the whole product is "run a well-known library over bytes the caller sent us." No numpy/scipy
(avoids the known Cloud Run Buildpacks failure -- no Fortran compiler for scipy's source build -- see
`skills/infra-deploy-ops`; none of these libraries need them anyway).

## Why $0.01-$0.02 (vs $0.35 for agent-verification-api, $0.01 for url-metadata-api)

No paid third-party API cost here (unlike WHOIS in `live-entity-verification`/`agent-verification-api`) --
pure CPU/memory cost, so this sits in the same low tier as `url-metadata-api`'s $0.01 single-fetch rather
than anywhere near `agent-verification-api`'s $0.35. PDF operations (`extract-pdf-to-json`,
`generate-pdf-from-json`) are priced a notch higher ($0.02) than docx/xlsx ($0.01): `pdfplumber`/`reportlab`
do meaningfully more work per call (page-level layout parsing / PDF rendering) than `python-docx`/`openpyxl`
(straight XML parsing of a zip archive). This asset is expected to be the most predictable of the 3 manual
candidates rather than the top earner -- document conversion is a common, low-variance agent need, not a
differentiated/rare capability -- so pricing favors consistent low-friction usage over per-call margin.

## Two risks this asset has that the other 3 manual assets don't

1. **CPU-bound, not I/O-bound.** Every parser/generator call is synchronous (no async API in any of the 4
   libraries), unlike the other 3 assets which are I/O-bound via `httpx.AsyncClient`. Every handler offloads
   the actual work via `asyncio.to_thread()` inside an `asyncio.wait_for()` timeout (25s) so one caller's
   slow parse never blocks the whole event loop / every concurrent request.
   **Known residual limitation**: `asyncio.wait_for()` cancels the *awaiting* task, it cannot kill the
   underlying OS thread -- Python has no API to forcibly terminate a running thread. A pathological input
   that hangs `pdfminer`/`openpyxl` internally keeps that one worker thread occupied indefinitely even after
   the caller gets a 504. Mitigated, not solved: a bounded semaphore (`NEXUS_MAX_CONCURRENT_JOBS`, default 4)
   caps how many such "leaked" threads can accumulate concurrently -- new requests get a clean 503 instead of
   unbounded thread growth, but an already-leaked thread is never reclaimed. A full fix would need the CPU-
   bound work in a separate, killable process (`ProcessPoolExecutor` + hard terminate) rather than a thread;
   not done here as disproportionate for a 7-day probation candidate.
2. **Decompression-bomb / resource-exhaustion.** `.docx`/`.xlsx` are zip archives -- a crafted file with a
   small compressed size but a huge uncompressed size (zip bomb) is a real DoS vector distinct from anything
   the other 3 assets face. `_check_zip_bomb_safe()` inspects the zip central directory (`zipfile.infolist()`,
   cheap, does NOT decompress entry data) before handing bytes to `python-docx`/`openpyxl`: rejects if total
   uncompressed size would exceed 50MB, or if any single entry's compression ratio exceeds 100x. Every upload
   is also capped at 8MB raw/decoded bytes before any parsing at all (PDFs included, even though they aren't
   zip-based -- bounds worst-case input size regardless of format).

## Known limitations (left unfixed on purpose -- CLAUDE.md §3, no gate without evidence it's needed)

- **MCP tool calls are not charged.** Same in-process-call pattern (and same reason) as the sibling manual
  assets: the MCP tool calls the shared conversion function directly, not via HTTP re-entry into the ASGI app.
- **No per-caller rate limiting.** Fine for a 7-day disposable measurement; add if it survives.
- **Generated documents are not validated for round-trip fidelity beyond what's smoke-tested locally** --
  `reportlab`'s table/paragraph rendering and `python-docx`'s heading-level mapping are both mature,
  widely-used code paths, not re-verified against every possible Office/PDF reader here.
- See the "CPU-bound" risk above for the thread-leak residual limitation.

## NEXUS_X402_FREE_MODE

Same gate pattern as `similarity-search-api`/`live-entity-verification` (`skills/x402-payments`) -- default
`false` (charges from day 1, no freemium window; engine has no external validation dependency the way
`live-entity-verification`'s WHOIS-based engine did, so there's no equivalent "already proven in production"
argument for skipping straight to paid -- it's charged anyway, per the session brief's "moderate and stable"
revenue framing, not because of a specific precedent). Set `true` locally for testing without a real facilitator
round-trip.

## Deploy target: Cloud Run, not Railway

Same pipeline as candidates #3/#4 -- see `skills/infra-deploy-ops`. **Memory bumped to 1Gi** (vs. the shared
`scripts/deploy_cloud_run.sh`'s hardcoded 512Mi default) -- this is the heaviest-in-memory of the 3 manual
candidates (PDF/Office parsing libraries, `pypdfium2`/`Pillow` transitively via `pdfplumber`). Deployed
directly via `gcloud run deploy` (not through the shared script, to avoid editing shared infra tooling for a
one-candidate memory bump):

```bash
# 1. First deploy -- PUBLIC_DOMAIN not known yet, every real request 421s until step 2.
gcloud run deploy document-conversion-api \
  --source manual_assets/document-conversion-api \
  --project nexus-505016 --region us-central1 \
  --allow-unauthenticated --min-instances=0 --max-instances=3 --memory=1Gi --quiet \
  --env-vars-file manual_assets/document-conversion-api/env-vars.deploy.yaml

# 2. Grab the printed *.run.app URL, then:
gcloud run services update document-conversion-api --region us-central1 --project nexus-505016 \
    --update-env-vars PUBLIC_DOMAIN=<the-real-domain>
```

## Measurement (candidate #6, 7-day window)

7-day window from first real deploy. Source of truth: `traffic_events`/`revenue_events`/`mcp_call_events`
tables (`asset_name = 'document-conversion-api'`), not Cloud Run logs. Day 7: if zero real traffic (filtering
crawlers), pause/delete the Cloud Run service, same decision rule as candidates #3/#4.
