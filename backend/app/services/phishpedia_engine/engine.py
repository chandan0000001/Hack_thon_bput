"""Stage-2 engine orchestration: screenshot -> brand -> domain consistency.

Lazy, cached, and failure-tolerant by design:
  * artifacts/models load once (module singletons, thread-locked)
  * device selection prefers CUDA, falls back to CPU; when an ONNX export of
    the detector is present next to the PyTorch weights it is preferred
    (onnxruntime is lighter than torch for CPU-only sidecars)
  * any failure returns None — Stage 2 is additive evidence and must never
    take down the URL pipeline

Artifact layout (see README.md for the fetch step):
    ml/data/phishpedia/
      faster_rcnn_logo_detector.pt   # Phishpedia detector weights
      siamese_logo_embedder.pt       # Phishpedia Siamese weights
      domain_map.pkl                 # brand -> legit domains (+ embeddings)
      faster_rcnn_logo_detector.onnx # optional ONNX export (preferred)
"""

from __future__ import annotations

import base64
import logging
import threading
from io import BytesIO
from pathlib import Path

from app.services.phishpedia_engine.logo_matching import (
    DEFAULT_MATCH_THRESHOLD,
    load_domain_map,
    match_logo,
)
from app.services.phishpedia_engine.logo_recog import (
    DETECTION_SCORE_THRESHOLD,
    crop_to_tensor,
    detect_logo_regions,
)

logger = logging.getLogger("cyberguard.phishpedia")

BACKEND_DIR = Path(__file__).resolve().parents[3]
ARTIFACT_DIR = BACKEND_DIR / "ml" / "data" / "phishpedia"

_DETECTOR_PATH = ARTIFACT_DIR / "faster_rcnn_logo_detector.pt"
_EMBEDDER_PATH = ARTIFACT_DIR / "siamese_logo_embedder.pt"
_DETECTOR_ONNX_PATH = ARTIFACT_DIR / "faster_rcnn_logo_detector.onnx"
_DOMAIN_MAP_PATH = ARTIFACT_DIR / "domain_map.pkl"

_LOCK = threading.Lock()
_STATE: dict[str, object] = {"loaded": False, "detector": None, "embedder": None,
                             "domain_map": None, "device": None, "onnx_session": None,
                             "disabled_reason": None}


def engine_available() -> bool:
    """True when every artifact file exists (models still load lazily)."""
    return _DETECTOR_PATH.exists() and _EMBEDDER_PATH.exists() and _DOMAIN_MAP_PATH.exists()


def _pick_device() -> str:
    try:
        import torch

        return "cuda" if torch.cuda.is_available() else "cpu"
    except Exception:
        return "cpu"


def _ensure_loaded() -> bool:
    if _STATE["loaded"]:
        return _STATE["detector"] is not None or _STATE["onnx_session"] is not None
    with _LOCK:
        if _STATE["loaded"]:
            return _STATE["detector"] is not None or _STATE["onnx_session"] is not None
        if not engine_available():
            _STATE["disabled_reason"] = (
                "pretrained artifacts missing — run the fetch step in "
                "app/services/phishpedia_engine/README.md to enable Stage 2"
            )
            _STATE["loaded"] = True
            return False
        try:
            device = _pick_device()
            domain_map = load_domain_map(_DOMAIN_MAP_PATH)

            onnx_session = None
            detector = None
            embedder = None
            if _DETECTOR_ONNX_PATH.exists():
                try:
                    import onnxruntime as ort

                    onnx_session = ort.InferenceSession(
                        str(_DETECTOR_ONNX_PATH), providers=["CPUExecutionProvider"]
                    )
                    logger.info("phishpedia: ONNX logo detector active")
                except Exception as exc:
                    logger.warning("phishpedia: ONNX detector unavailable (%s) — falling back to PyTorch", exc)
            if onnx_session is None:
                from app.services.phishpedia_engine.models import build_logo_detector

                detector = build_logo_detector(_DETECTOR_PATH, device)
            from app.services.phishpedia_engine.models import SiameseNet

            embedder = SiameseNet(_EMBEDDER_PATH, device)

            _STATE.update({"loaded": True, "detector": detector, "embedder": embedder,
                           "domain_map": domain_map, "device": device, "onnx_session": onnx_session,
                           "disabled_reason": None})
            logger.info("phishpedia engine loaded (device=%s, brands=%d, onnx=%s)",
                        device, len(domain_map), onnx_session is not None)
            return True
        except Exception as exc:
            _STATE.update({"loaded": True, "disabled_reason": f"engine load failed: {exc}"})
            logger.warning("phishpedia engine disabled: %s", exc)
            return False


def _decode_image(image_bytes: bytes):
    from PIL import Image

    return Image.open(BytesIO(image_bytes)).convert("RGB")


def analyze_screenshot(
    url: str,
    image_bytes: bytes,
    match_threshold: float = DEFAULT_MATCH_THRESHOLD,
    detection_threshold: float = DETECTION_SCORE_THRESHOLD,
) -> dict | None:
    """Run Stage 2 on one screenshot.

    Returns:
        {
          "engine": "phishpedia",
          "logos_detected": int,
          "brand_detected": str | None,
          "phishpedia_confidence": float,      # detection score of the logo
          "brand_similarity": float | None,    # Siamese cosine similarity
          "matched_legitimate_domain": str | None,
          "domain_brand_consistent": bool | None,
        }
        or None when the engine is unavailable (Stage 1 stands alone).
    """
    if not image_bytes or not _ensure_loaded():
        return None

    from app.core.url_reputation import get_registrable_domain

    try:
        import torch
        from torchvision import transforms as _tv_transforms

        image = _decode_image(image_bytes)
        input_tensor = _tv_transforms.Compose([_tv_transforms.ToTensor()])(image).unsqueeze(0)

        detector = _STATE["onnx_session"]
        if detector is not None:
            # ONNX path: sessions expose the same detection contract via the
            # exported graph; regions come back as numpy arrays.
            regions = _detect_via_onnx(detector, input_tensor, detection_threshold)
        else:
            regions = detect_logo_regions(_STATE["detector"], input_tensor, torch, detection_threshold)

        embedder = _STATE["embedder"]
        registrable = get_registrable_domain((url or "").split("//")[-1].split("/")[0].lower())
        best = None
        for box, score in regions[:3]:  # top-3 regions like Phishpedia
            crop_tensor = crop_to_tensor(image, box, torch, None)
            embedding = embedder.embed(crop_tensor)
            match = match_logo(embedding, _STATE["domain_map"], threshold=match_threshold)
            if match and (best is None or match["brand_similarity"] > best["brand_similarity"]):
                match["phishpedia_confidence"] = round(float(score), 4)
                match["logos_detected"] = len(regions)
                best = match

        result = {
            "engine": "phishpedia",
            "logos_detected": len(regions),
            "brand_detected": best["brand"] if best else None,
            "phishpedia_confidence": best["phishpedia_confidence"] if best else 0.0,
            "brand_similarity": best["brand_similarity"] if best else None,
            "matched_legitimate_domain": best["legitimate_domain"] if best else None,
            "domain_brand_consistent": (
                bool(best["legitimate_domain"]) and registrable == best["legitimate_domain"]
            ) if best else None,
        }
        return result
    except Exception as exc:
        logger.warning("phishpedia analysis failed: %s", exc)
        return None


def _detect_via_onnx(session, image_tensor, threshold: float):
    """Faster R-CNN ONNX export inference (boxes/scores)."""
    import numpy as np

    inputs = {"images": image_tensor.numpy()}
    outputs = session.run(None, inputs)
    boxes, scores = outputs[0], outputs[1]
    regions = []
    for box, score in zip(boxes, scores):
        if float(score) >= threshold:
            regions.append(([float(v) for v in box], float(score)))
    regions.sort(key=lambda item: item[1], reverse=True)
    return regions
