"""CyberGuard Phishpedia engine — Stage 2 visual brand verification.

Minimal inference-only extraction of the Phishpedia pipeline
(https://github.com/lindsey98/Phishpedia — see LICENSE in that repository):
logo detection (Faster R-CNN) + Siamese logo matching against a reference
brand list. Only the components needed for inference live here
(`models.py`, `logo_recog.py`, `logo_matching.py`, `engine.py`); training
code, crawl data and scraping utilities are intentionally NOT vendored.

Public API:
    analyze_screenshot(url, image_bytes) -> dict | None

The engine returns None whenever the pretrained artifacts are missing or the
model stack is unavailable — Stage 2 is strictly additive evidence and must
never break Stage 1. Artifacts are NOT committed to this repository; see
README.md in this directory for the one-time fetch step.
"""

from app.services.phishpedia_engine.engine import analyze_screenshot, engine_available

__all__ = ["analyze_screenshot", "engine_available"]
