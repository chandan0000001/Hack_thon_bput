# Phishpedia Stage-2 engine (minimal inference extraction)

This directory contains a **minimal, inference-only** extraction of the
Phishpedia pipeline (https://github.com/lindsey98/Phishpedia), per the
CyberGuard constraint: do NOT vendor the whole repository (training code,
crawl/scrape tooling, and the 500MB+ data release stay out of this codebase).

## What is vendored here

| File | Upstream origin | Contents |
| --- | --- | --- |
| `models.py` | `phishpedia.py`, `models.py` | Faster R-CNN (ResNet-50-FPN, 1-class logo head) builder + Siamese ResNet-50 embedding net |
| `logo_recog.py` | `logo_recog.py` | logo region detection + crop-to-embedding-tensor |
| `logo_matching.py` | `logo_matching.py` | domain-map loading + Siamese cosine matching (brand, legit domain, similarity) |
| `engine.py` | (new orchestration) | lazy loading, device selection (CUDA → CPU), ONNX-preferred detector, brand↔domain consistency verdict |

Upstream license: Phishpedia is released for research use — review
`LICENSE`/usage terms at the upstream repository before production use.

## One-time artifact fetch (not committed to git)

Place these files under `backend/ml/data/phishpedia/`:

1. `faster_rcnn_logo_detector.pt` — Phishpedia's Faster R-CNN logo detector
   weights (upstream `models/brand_detector/faster_rcnn_from_pth`).
2. `siamese_logo_embedder.pt` — Phishpedia's Siamese network weights
   (upstream `models/brand_recognition/siamese`).
3. `domain_map.pkl` — Phishpedia's brand → legitimate-domain mapping
   (upstream `domain_map.pkl`; the loader also accepts an enriched
   `{brand: {"domains": [...], "embedding": [...]}}` variant with
   precomputed reference embeddings).

Optional:
4. `faster_rcnn_logo_detector.onnx` — an ONNX export of (1); when present it
   is preferred so CPU-only sidecars do not need torch at inference time.

A skeleton prepare script (from the upstream release or produced by running
the upstream `prepare` step once) is enough — the engine degrades to
`None` (Stage-1-only mode) when artifacts are missing, and the API marks the
Stage-2 evidence as unavailable rather than failing.

## Runtime shape

* The API never runs vision inline: `POST /analysis/url/visual` enqueues a
  `visual_phish_check` job for `app/workers/visual_worker.py` (launch with
  `python -m arq app.workers.visual_worker.WorkerSettings`, add a compose
  service mirroring the email-worker).
* Fused verdicts are cached in Redis under
  `visual_verdict:{registrable_domain}` with a 1-hour TTL.
* Fusion policy: `app/services/evidence_fusion.py` — explicit rules, no
  averaging. Stage 2 only runs when Stage 1 is suspicious.
