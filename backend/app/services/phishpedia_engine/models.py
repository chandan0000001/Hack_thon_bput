"""Minimal PyTorch module definitions for the Phishpedia inference engine.

Ported from Phishpedia (https://github.com/lindsey98/Phishpedia) — only the
inference-time modules, trimmed to what logo detection + Siamese matching
need:

  * build_logo_detector() — Faster R-CNN with a ResNet-50-FPN backbone and a
    single "logo" class (Phishpedia's `faster_rcnn_from_pth` shape).
  * SiameseNet — the two-branch embedding network that maps a cropped logo
    into the reference-embedding space (Phishpedia's `SiameseNet` with
    ResNet-50 backbone, pretrained on logo-brand pairs).

All heavy imports are function-local so importing this module (and therefore
the whole phishpedia_engine package) never pulls torch unless Stage 2 is
actually exercised.
"""

from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger("cyberguard.phishpedia")

NUM_LOGO_CLASSES = 2  # background + logo


def build_logo_detector(weights_path: Path, device: str):
    """Faster R-CNN (ResNet-50-FPN, 1-class head) loaded from a state dict."""
    import torch
    import torchvision
    from torchvision.models.detection.faster_rcnn import FastRCNNPredictor

    detector = torchvision.models.detection.fasterrcnn_resnet50_fpn(
        weights=None, trainable_backbone_layers=0
    )
    in_features = detector.roi_heads.box_predictor.cls_score.in_features
    detector.roi_heads.box_predictor = FastRCNNPredictor(in_features, NUM_LOGO_CLASSES)
    state = torch.load(weights_path, map_location="cpu", weights_only=True)
    if "model_state_dict" in state:
        state = state["model_state_dict"]
    detector.load_state_dict(state)
    detector.to(device).eval()
    return detector


class SiameseNet:
    """Lazy wrapper around the Phishpedia Siamese embedding network."""

    def __init__(self, weights_path: Path, device: str):
        import torch
        import torch.nn as nn
        from torchvision.models import resnet50

        class _Siamese(nn.Module):
            def __init__(self):
                super().__init__()
                backbone = resnet50(weights=None)
                self.encoder = nn.Sequential(*list(backbone.children())[:-1])

            def forward(self, x):
                return torch.flatten(self.encoder(x), 1)  # (B, 2048)

        self._torch = torch
        self.model = _Siamese()
        state = torch.load(weights_path, map_location="cpu", weights_only=True)
        if "model_state_dict" in state:
            state = state["model_state_dict"]
        self.model.load_state_dict(state)
        self.model.to(device).eval()

    def embed(self, tensor):
        """Image tensor (B, 3, H, W) normalized like Phishpedia -> (B, 2048)."""
        torch = self._torch
        with torch.no_grad():
            return self.model(tensor)
