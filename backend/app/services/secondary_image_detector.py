"""Secondary image detector (Model B): Lynote Sentry ConvNeXt Small adapter.

Lightweight, self-contained adapter around the Lynote `ai-image-detector`
Sentry backend (aidetector/sentry_adapter.py). It intentionally does NOT
import the Lynote application tree — only the minimum inference pieces are
reimplemented here:

  * timm ConvNeXt-Small with a 2-class head (pretrained=False)
  * the Sentry checkpoint key conversion (OpenMMLab -> timm naming)
  * the Sentry preprocessing (Resize 256 bicubic, CenterCrop 224, ImageNet-
    style normalization with timm's ConvNeXt constants)

Sentry fake-image checkpoints use class 0 for FAKE (AI-generated) and class
1 for REAL — the opposite order of CyberGuard Model A (deepfake_cnn_v2.pt,
class 1 = fake). The adapter normalises the output to `probability_ai`.

Loading is a thread-safe lazy singleton: the model is downloaded (Hugging
Face hub) or read (local weight path) once, cached, run with model.eval()
under torch.inference_mode(), and never re-initialised per request. Any
failure (missing timm/huggingface_hub, download error, corrupt weights,
inference timeout) degrades to available=False — the API must never fail
because the OPTIONAL secondary detector is unavailable.
"""

import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from io import BytesIO
from pathlib import Path
from typing import Any

from app.core.config import get_settings

logger = logging.getLogger("cyberguard.deepfake.secondary")

SECONDARY_MODEL_NAME = "Sentry ConvNeXt Small"
SECONDARY_BACKEND = "sentry-convnext-small"

# Upstream weight source (Lynote ai-image-detector, aidetector/config.py).
SENTRY_DEFAULT_HF_REPO = "InfImagine/Sentry_image_models"
SENTRY_CONVNEXT_SMALL_DIR = "convnext_small_4xb256_fake5m-lr4e-4"
SENTRY_CONVNEXT_SMALL_FILE = f"{SENTRY_CONVNEXT_SMALL_DIR}/epoch_15.pth"

# Sentry fake-image checkpoints: logit index 0 = fake (AI), 1 = real.
FAKE_CLASS_INDEX = 0
REAL_CLASS_INDEX = 1

# Thread-safe lazy singleton state (mirrors app.services.ml_inference).
_secondary_bundle: dict[str, Any] | None = None
_secondary_lock = threading.Lock()
_secondary_executor: ThreadPoolExecutor | None = None
_executor_lock = threading.Lock()


def _get_executor() -> ThreadPoolExecutor:
    """Single worker used to bound inference time by the configured timeout."""
    global _secondary_executor
    if _secondary_executor is None:
        with _executor_lock:
            if _secondary_executor is None:
                _secondary_executor = ThreadPoolExecutor(
                    max_workers=1, thread_name_prefix="sentry-model-b"
                )
    return _secondary_executor


def secondary_model_status() -> dict[str, Any]:
    """Deployment info about Model B (never loads weights as a side effect)."""
    settings = get_settings()
    bundle = _secondary_bundle
    return {
        "model": SECONDARY_MODEL_NAME,
        "backend": SECONDARY_BACKEND,
        "enabled": settings.DEEPFAKE_SECONDARY_ENABLED,
        "loaded": bool(bundle and bundle.get("model") is not None),
        "weight_source": (bundle or {}).get("weight_source"),
        "device": (bundle or {}).get("device"),
        "error": (bundle or {}).get("error"),
    }


def _resolve_weight_path(settings) -> tuple[Path | None, str]:
    """Local weight path override, or None to use the Hugging Face hub."""
    configured = (settings.DEEPFAKE_SECONDARY_WEIGHT_PATH or "").strip()
    if configured:
        path = Path(configured)
        if not path.is_absolute():
            path = Path.cwd() / path
        return path, f"local:{configured}"
    return None, f"hf-hub:{settings.DEEPFAKE_SECONDARY_HF_REPO}/{SENTRY_CONVNEXT_SMALL_FILE}"


def _load_secondary_model() -> dict[str, Any]:
    """Load Sentry ConvNeXt Small once; cache success OR the failure state."""
    settings = get_settings()
    bundle: dict[str, Any] = {
        "model": None,
        "weight_source": None,
        "device": None,
        "error": None,
    }
    try:
        import torch
        import timm
        from huggingface_hub import hf_hub_download

        device_name = (settings.DEEPFAKE_SECONDARY_DEVICE or "cpu").strip() or "cpu"
        device = torch.device(device_name)
        weight_path, weight_source = _resolve_weight_path(settings)
        if weight_path is None:
            weight_path = Path(
                hf_hub_download(
                    repo_id=settings.DEEPFAKE_SECONDARY_HF_REPO,
                    filename=SENTRY_CONVNEXT_SMALL_FILE,
                )
            )

        model = timm.create_model("convnext_small", pretrained=False, num_classes=2)
        checkpoint = torch.load(str(weight_path), map_location="cpu", weights_only=False)
        state_dict = (
            checkpoint["state_dict"]
            if isinstance(checkpoint, dict) and "state_dict" in checkpoint
            else checkpoint
        )
        converted = convert_sentry_convnext_state_dict(state_dict)
        missing, unexpected = model.load_state_dict(converted, strict=False)
        if unexpected:
            raise RuntimeError(f"Unexpected Sentry checkpoint keys: {unexpected[:10]}")
        required_missing = [key for key in missing if not key.startswith("head.norm")]
        if required_missing:
            raise RuntimeError(f"Missing required Sentry checkpoint keys: {required_missing[:10]}")
        model.to(device).eval()

        bundle.update(model=model, weight_source=weight_source, device=str(device))
        logger.info(
            "deepfake_model_b_loaded model=%s backend=%s weight_source=%s device=%s",
            SECONDARY_MODEL_NAME,
            SECONDARY_BACKEND,
            weight_source,
            device,
        )
    except Exception as exc:
        # Cache the unavailable state: predictable degradation, no repeated
        # expensive download attempts inside the request path.
        bundle["error"] = str(exc)
        logger.warning(
            "deepfake_secondary_failure backend=%s error=%s — "
            "deepfake detection continues with Model A + forensics",
            SECONDARY_BACKEND,
            exc,
        )
    return bundle


def get_secondary_model():
    """Thread-safe lazy singleton accessor; returns the nn.Module or None."""
    if not get_settings().DEEPFAKE_SECONDARY_ENABLED:
        return None
    global _secondary_bundle
    if _secondary_bundle is not None:
        return _secondary_bundle["model"]
    with _secondary_lock:
        if _secondary_bundle is None:
            _secondary_bundle = _load_secondary_model()
    return _secondary_bundle["model"]


def _preprocess_sentry_image(image):
    """Preprocessing expected by the Sentry ConvNeXt checkpoint (Lynote parity)."""
    import torch
    import torchvision.transforms as T

    transform = T.Compose(
        [
            T.Resize(256, interpolation=T.InterpolationMode.BICUBIC),
            T.CenterCrop(224),
            T.ToTensor(),
            T.Normalize(
                mean=[123.675 / 255.0, 116.28 / 255.0, 103.53 / 255.0],
                std=[58.395 / 255.0, 57.12 / 255.0, 57.375 / 255.0],
            ),
        ]
    )
    return transform(image.convert("RGB"))


def convert_sentry_convnext_state_dict(state_dict: dict) -> dict:
    """Map OpenMMLab Sentry ConvNeXt keys onto timm's convnext_small naming.

    Reimplemented from Lynote aidetector/sentry_adapter.py so CyberGuard does
    not depend on the Lynote package itself.
    """
    converted: dict[str, Any] = {}
    for key, value in state_dict.items():
        if not key.startswith(("backbone.", "head.")):
            continue
        new_key = key.replace("backbone.downsample_layers.0.0.", "stem.0.")
        new_key = new_key.replace("backbone.downsample_layers.0.1.", "stem.1.")
        for stage_index in range(1, 4):
            new_key = new_key.replace(
                f"backbone.downsample_layers.{stage_index}.0.",
                f"stages.{stage_index}.downsample.0.",
            )
            new_key = new_key.replace(
                f"backbone.downsample_layers.{stage_index}.1.",
                f"stages.{stage_index}.downsample.1.",
            )
        for stage_index in range(4):
            new_key = new_key.replace(
                f"backbone.stages.{stage_index}.",
                f"stages.{stage_index}.blocks.",
            )
        new_key = new_key.replace(".depthwise_conv.", ".conv_dw.")
        new_key = new_key.replace(".pointwise_conv1.", ".mlp.fc1.")
        new_key = new_key.replace(".pointwise_conv2.", ".mlp.fc2.")
        new_key = new_key.replace("backbone.norm3.", "head.norm.")
        converted[new_key] = value
    return converted


def _run_with_timeout(fn, *args):
    """Run a callable under the configured DEEPFAKE_SECONDARY_TIMEOUT_SECONDS."""
    settings = get_settings()
    timeout = max(1, int(settings.DEEPFAKE_SECONDARY_TIMEOUT_SECONDS))
    future = _get_executor().submit(fn, *args)
    return future.result(timeout=timeout)


def _infer(model, tensor):
    import torch

    with torch.inference_mode():
        logits = model(tensor).detach().cpu()
        probabilities = torch.softmax(logits, dim=-1)
    return probabilities[0]


def predict_secondary_image(image_bytes: bytes) -> dict[str, Any]:
    """Model B inference: probability the image is AI-generated/manipulated.

    Returns the adapter contract:
        {
            "probability_ai": float,   # 0-1, Sentry class-0 (fake) softmax
            "label": str,              # "ai" | "real" (0.5 threshold)
            "model": str,              # human-readable model name
            "backend": str,            # "sentry-convnext-small"
            "available": bool,         # False on any failure — never raises
            "error": str               # present only when available is False
        }
    """
    settings = get_settings()
    result: dict[str, Any] = {
        "probability_ai": 0.0,
        "label": "real",
        "model": SECONDARY_MODEL_NAME,
        "backend": SECONDARY_BACKEND,
        "available": False,
    }
    if not settings.DEEPFAKE_SECONDARY_ENABLED or not settings.ML_ENABLED:
        result["error"] = "secondary image detector disabled by configuration"
        return result

    model = get_secondary_model()
    if model is None:
        result["error"] = (
            _secondary_bundle.get("error") if _secondary_bundle else "model not loaded"
        ) or "secondary model unavailable"
        return result

    try:
        import torch
        from PIL import Image

        image = Image.open(BytesIO(image_bytes))
        image.load()
        tensor = _preprocess_sentry_image(image).unsqueeze(0).to(next(model.parameters()).device)
        row = _run_with_timeout(_infer, model, tensor)
        probability_ai = float(row[FAKE_CLASS_INDEX].item())
        result["probability_ai"] = round(probability_ai, 4)
        result["label"] = "ai" if probability_ai >= 0.5 else "real"
        result["available"] = True
        logger.debug(
            "secondary image inference complete probability_ai=%.4f", probability_ai
        )
    except Exception as exc:
        result["error"] = str(exc)
        logger.warning(
            "deepfake_secondary_failure stage=inference error=%s — "
            "continuing with Model A + forensics only",
            exc,
        )
    return result
