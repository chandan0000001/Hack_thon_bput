"""Logo region detection and embedding (Phishpedia inference subset).

logo_recog.py in the upstream repository mixes detection with dataset/crawl
utilities; only the two operations Stage 2 needs live here:
  * detect_logo_regions() — Faster R-CNN forward pass returning logo boxes
  * embed_logo_crop()     — crop -> normalize -> Siamese embedding
"""

from __future__ import annotations

import logging

logger = logging.getLogger("cyberguard.phishpedia")

# Faster R-CNN score below which a detected region is ignored.
DETECTION_SCORE_THRESHOLD = 0.6
# Phishpedia normalizes crops to this square before the Siamese encoder.
EMBED_INPUT_SIZE = 127


def detect_logo_regions(detector, image_tensor, torch, score_threshold: float = DETECTION_SCORE_THRESHOLD):
    """Run the logo detector; return list of (box, score) with box = [x0,y0,x1,y1]."""
    with torch.no_grad():
        outputs = detector(image_tensor)[0]
    regions = []
    for box, score in zip(outputs.get("boxes", []), outputs.get("scores", [])):
        if float(score) >= score_threshold:
            regions.append((box.tolist(), float(score)))
    regions.sort(key=lambda item: item[1], reverse=True)
    return regions


def crop_to_tensor(image_pil, box, torch, torchvision_transforms, size: int = EMBED_INPUT_SIZE):
    """PIL image + box -> normalized (1, 3, size, size) tensor."""
    from torchvision import transforms

    crop = image_pil.crop((box[0], box[1], box[2], box[3])).convert("RGB").resize((size, size))
    transform = transforms.Compose([
        transforms.ToTensor(),
        transforms.Normalize(mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225]),
    ])
    return transform(crop).unsqueeze(0)
