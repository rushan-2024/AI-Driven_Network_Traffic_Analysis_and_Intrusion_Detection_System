"""Regenerate the synthetic sample datasets in data/samples (deterministic)."""
import _path  # noqa: F401
from src.config import SAMPLES_DIR
from src.synthetic import write_samples

if __name__ == "__main__":
    for p in write_samples(SAMPLES_DIR):
        print("wrote", p.relative_to(SAMPLES_DIR.parent.parent))
