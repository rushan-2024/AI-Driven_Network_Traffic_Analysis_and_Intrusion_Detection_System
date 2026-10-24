import io

import pytest

from src.config import DetectionConfig
from src.detection import load_default_model
from src.pipeline import analyze_scenario, ensure_samples


@pytest.fixture(scope="session")
def cfg():
    ensure_samples()
    return DetectionConfig()


@pytest.fixture(scope="session")
def model(cfg):
    m, info = load_default_model(cfg)
    assert m is not None, info
    return m


@pytest.fixture(scope="session")
def analyses(cfg, model):
    from src.synthetic import SCENARIO_ORDER
    return {k: analyze_scenario(k, cfg, model) for k in SCENARIO_ORDER}


def csv(text: str):
    return io.StringIO(text.strip() + "\n")
