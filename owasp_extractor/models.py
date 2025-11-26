"""
OWASP Security Rule 数据模型定义

用于定义从OWASP CheatSheet中提取的结构化安全规则
"""
from typing import Optional, List
from pydantic import BaseModel, Field
from enum import Enum


class Severity(str, Enum):
    """严重程度枚举"""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class VulnerabilityType(str, Enum):
    """漏洞类型枚举"""
    SQL_INJECTION = "SQL Injection"
    XSS = "Cross-Site Scripting (XSS)"
    CSRF = "Cross-Site Request Forgery (CSRF)"
    COMMAND_INJECTION = "Command Injection"
    XPATH_INJECTION = "XPath Injection"
    LDAP_INJECTION = "LDAP Injection"
    DESERIALIZATION = "Insecure Deserialization"
    XXE = "XML External Entity (XXE)"
    SSRF = "Server-Side Request Forgery (SSRF)"
    BROKEN_AUTH = "Broken Authentication"
    SENSITIVE_DATA_EXPOSURE = "Sensitive Data Exposure"
    BROKEN_ACCESS_CONTROL = "Broken Access Control"
    SECURITY_MISCONFIGURATION = "Security Misconfiguration"
    INSUFFICIENT_LOGGING = "Insufficient Logging"
    WEAK_CRYPTOGRAPHY = "Weak Cryptography"
    FILE_UPLOAD = "Insecure File Upload"
    INPUT_VALIDATION = "Input Validation"
    SESSION_MANAGEMENT = "Session Management"
    PROTOTYPE_POLLUTION = "Prototype Pollution"
    DOM_CLOBBERING = "DOM Clobbering"
    CLICKJACKING = "Clickjacking"
    OPEN_REDIRECT = "Open Redirect"
    OTHER = "Other"


class OWASPSecurityRule(BaseModel):
    """OWASP 安全规则数据结构
    
    用于构建向量化知识库的结构化数据
    """
    rule_name: str = Field(
        description="规则名称，例如 'Java中防止SQL注入'"
    )
    language: str = Field(
        description="代码的编程语言，如 Java, Python, JavaScript, C#, PHP, Ruby, General"
    )
    vulnerability: str = Field(
        description="关联的漏洞类型，如 XSS, SQL Injection, CSRF, Weak Cryptography"
    )
    severity: str = Field(
        description="严重程度: Critical, High, Medium, Low (OWASP通常都是高危)"
    )
    rationale: str = Field(
        description="为什么这样做能防御攻击？详细解释防御原理"
    )
    bad_code: Optional[str] = Field(
        default=None,
        description="易受攻击的代码示例。如果原文未提供，根据漏洞描述生成一个典型的错误写法"
    )
    good_code: str = Field(
        description="安全的防御性代码示例，展示正确的实现方式"
    )
    description: str = Field(
        description="用于向量检索的摘要，包含漏洞关键词和防御手段，适合作为RAG检索的内容"
    )
    source_file: str = Field(
        description="来源文件名"
    )
    section: str = Field(
        default="",
        description="来源章节/段落"
    )
    tags: List[str] = Field(
        default_factory=list,
        description="相关标签，用于分类检索"
    )
    
    class Config:
        """Pydantic配置"""
        json_schema_extra = {
            "example": {
                "rule_name": "Java中使用PreparedStatement防止SQL注入",
                "language": "Java",
                "vulnerability": "SQL Injection",
                "severity": "Critical",
                "rationale": "使用参数化查询可以确保用户输入被当作数据而不是SQL代码处理,数据库会自动区分代码和数据,从而阻止攻击者注入恶意SQL语句",
                "bad_code": 'String query = "SELECT * FROM users WHERE name = \'" + userInput + "\'";\nStatement stmt = conn.createStatement();\nResultSet rs = stmt.executeQuery(query);',
                "good_code": 'String query = "SELECT * FROM users WHERE name = ?";\nPreparedStatement pstmt = conn.prepareStatement(query);\npstmt.setString(1, userInput);\nResultSet rs = pstmt.executeQuery();',
                "description": "SQL注入防御: 在Java应用中使用PreparedStatement参数化查询代替字符串拼接,确保用户输入作为参数值而非SQL代码执行",
                "source_file": "SQL_Injection_Prevention_Cheat_Sheet.md",
                "section": "Defense Option 1: Prepared Statements",
                "tags": ["SQL注入", "Java", "PreparedStatement", "参数化查询", "数据库安全"]
            }
        }


class MarkdownChunk(BaseModel):
    """Markdown文档分片结构"""
    file_name: str = Field(description="源文件名")
    title: str = Field(description="文档主标题")
    section_title: str = Field(description="章节标题")
    section_level: int = Field(description="标题层级 (1-6)")
    content: str = Field(description="章节内容")
    code_blocks: List[dict] = Field(
        default_factory=list,
        description="代码块列表，每个包含language和code"
    )
    parent_sections: List[str] = Field(
        default_factory=list,
        description="父级章节标题链"
    )
    chunk_index: int = Field(description="分片索引")
    

class ExtractionResult(BaseModel):
    """提取结果"""
    success: bool = Field(description="是否成功")
    rules: List[OWASPSecurityRule] = Field(
        default_factory=list,
        description="提取的安全规则列表"
    )
    source_file: str = Field(description="源文件名")
    chunk_count: int = Field(description="处理的分片数量")
    error_message: Optional[str] = Field(
        default=None,
        description="错误信息(如果失败)"
    )


class PipelineConfig(BaseModel):
    """流水线配置"""
    # LLM配置
    llm_provider: str = Field(
        default="openai",
        description="LLM服务商: openai, azure, anthropic, deepseek, ollama, custom"
    )
    llm_model: str = Field(
        default="gpt-4o-mini",
        description="模型名称"
    )
    llm_api_key: Optional[str] = Field(
        default=None,
        description="API密钥"
    )
    llm_base_url: Optional[str] = Field(
        default=None,
        description="自定义API基础URL"
    )
    llm_temperature: float = Field(
        default=0.1,
        description="生成温度，越低越确定"
    )
    llm_max_tokens: int = Field(
        default=4096,
        description="最大输出token数"
    )
    
    # 分片配置
    chunk_min_length: int = Field(
        default=100,
        description="最小分片长度"
    )
    chunk_max_length: int = Field(
        default=8000,
        description="最大分片长度"
    )
    include_code_blocks: bool = Field(
        default=True,
        description="是否必须包含代码块"
    )
    
    # 输出配置
    output_dir: str = Field(
        default="./output",
        description="输出目录"
    )
    output_format: str = Field(
        default="jsonl",
        description="输出格式: json, jsonl, csv"
    )
    
    # 并发配置
    max_concurrent: int = Field(
        default=3,
        description="最大并发请求数"
    )
    retry_count: int = Field(
        default=3,
        description="重试次数"
    )
    retry_delay: float = Field(
        default=1.0,
        description="重试延迟(秒)"
    )
