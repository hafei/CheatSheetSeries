"""
OWASP CheatSheet 安全规则提取器

将OWASP CheatSheet Markdown文档分片并提取结构化的安全编码规范
"""

from .models import OWASPSecurityRule, MarkdownChunk, ExtractionResult, PipelineConfig
from .chunker import MarkdownChunker, MarkdownSection, CodeBlock
from .pipeline import OWASPExtractionPipeline, run_extraction
from .llm_client import create_llm_client, BaseLLMClient

__version__ = "0.1.0"
__all__ = [
    # 数据模型
    "OWASPSecurityRule",
    "MarkdownChunk", 
    "ExtractionResult",
    "PipelineConfig",
    # 分片器
    "MarkdownChunker",
    "MarkdownSection",
    "CodeBlock",
    # 流水线
    "OWASPExtractionPipeline",
    "run_extraction",
    # LLM客户端
    "create_llm_client",
    "BaseLLMClient",
]
