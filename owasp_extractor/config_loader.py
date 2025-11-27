"""
Configuration loader for owasp_extractor

Responsibilities:
- Search for a YAML config file (explicit path, env var, default paths)
- Parse YAML and validate/coerce into PipelineConfig (from models.py)
- Provide helpful errors and sensible defaults
"""
import os
import logging
from pathlib import Path
from typing import Optional, Dict, Any

try:
    import yaml
except Exception:  # pragma: no cover - if pyyaml missing we'll raise below
    yaml = None

from .models import PipelineConfig

logger = logging.getLogger(__name__)


class ConfigError(Exception):
    pass


def _load_yaml_file(path: Path) -> Dict[str, Any]:
    if yaml is None:
        raise ConfigError("PyYAML is required to load YAML configuration. Please install pyyaml.")

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
            return data
    except Exception as e:
        raise ConfigError(f"Failed to read config file {path}: {e}")


def _map_config(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Map nested YAML structure to PipelineConfig fields."""
    cfg: Dict[str, Any] = {}

    llm = raw.get("llm", {}) or {}
    chunking = raw.get("chunking", {}) or {}
    runtime = raw.get("runtime", {}) or {}
    output = raw.get("output", {}) or {}

    cfg.update({
        # llm
        "llm_provider": llm.get("provider") if llm.get("provider") is not None else None,
        "llm_model": llm.get("model") if llm.get("model") is not None else None,
        "llm_api_key": llm.get("api_key") if llm.get("api_key") is not None else None,
        "llm_base_url": llm.get("base_url") if llm.get("base_url") is not None else None,
        "llm_temperature": llm.get("temperature") if llm.get("temperature") is not None else None,
        "llm_max_tokens": llm.get("max_tokens") if llm.get("max_tokens") is not None else None,
        # chunking
        "chunk_min_length": chunking.get("min_length") if chunking.get("min_length") is not None else None,
        "chunk_max_length": chunking.get("max_length") if chunking.get("max_length") is not None else None,
        "include_code_blocks": chunking.get("require_code") if chunking.get("require_code") is not None else None,
        # runtime
        "max_concurrent": runtime.get("max_concurrent") if runtime.get("max_concurrent") is not None else None,
        "retry_count": runtime.get("retry_count") if runtime.get("retry_count") is not None else None,
        "retry_delay": runtime.get("retry_delay") if runtime.get("retry_delay") is not None else None,
        # output
        "output_dir": output.get("dir") if output.get("dir") is not None else None,
        "output_format": output.get("format") if output.get("format") is not None else None,
    })

    # Remove None entries to allow pydantic defaults to kick in
    return {k: v for k, v in cfg.items() if v is not None}


def load_config(path: Optional[str] = None) -> PipelineConfig:
    """Load configuration from YAML file.

    Search order:
    1. explicit `path` argument
    2. env var `OWASP_EXTRACTOR_CONFIG`
    3. ./owasp_extractor/config.yaml
    4. ./owasp_extractor/config.example.yaml

    If no file is found, return default PipelineConfig with a warning.
    """
    search_paths = []

    if path:
        search_paths.append(Path(path))

    env_path = os.environ.get("OWASP_EXTRACTOR_CONFIG")
    if env_path:
        search_paths.append(Path(env_path))

    # Default local config locations
    search_paths.append(Path(__file__).parent / "config.yaml")
    search_paths.append(Path(__file__).parent / "config.example.yaml")

    found = None
    for p in search_paths:
        if p and p.exists():
            found = p
            break

    if not found:
        logger.warning("No configuration file found; using PipelineConfig defaults and environment variables where applicable.")
        return PipelineConfig()

    raw = _load_yaml_file(found)
    mapped = _map_config(raw)

    # Fallback for API key from common env vars if not provided in YAML
    provider = mapped.get("llm_provider") or raw.get("llm", {}).get("provider")
    if not mapped.get("llm_api_key"):
        # provider-specific env var mapping (keep in sync with llm_client)
        env_keys = {
            "openai": "OPENAI_API_KEY",
            "azure": "AZURE_OPENAI_API_KEY",
            "anthropic": "ANTHROPIC_API_KEY",
            "deepseek": "DEEPSEEK_API_KEY",
        }
        if provider and provider.lower() in env_keys:
            key = env_keys[provider.lower()]
            v = os.environ.get(key)
            if v:
                mapped["llm_api_key"] = v

    # Validate using Pydantic; prefer v2 `model_validate` if available
    try:
        parse_fn = getattr(PipelineConfig, "model_validate", None)
        if parse_fn is None:
            parse_fn = getattr(PipelineConfig, "parse_obj", None)
        if parse_fn is None:
            raise ConfigError("No compatible validation method found on PipelineConfig")
        cfg = parse_fn(mapped)
    except Exception as e:
        raise ConfigError(f"Configuration validation failed: {e}")

    logger.info(f"Loaded configuration from {found}")
    return cfg
