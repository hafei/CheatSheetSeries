# OWASP CheatSheet 安全规则提取器

将 OWASP CheatSheet 系列的 Markdown 文档智能分片，并利用大语言模型提取结构化的安全编码规范，用于构建代码安全知识库。

## 🎯 功能特点

- **智能分片**: 基于Markdown语义结构（标题层级）进行文档分片，保持上下文完整性
- **多LLM支持**: 支持 OpenAI、Azure、Anthropic、DeepSeek、Ollama 等多种LLM服务商
- **结构化输出**: 提取的安全规则包含漏洞类型、代码示例、防御原理等字段
- **中文输出**: 所有描述性字段输出中文，便于中文用户使用
- **并发处理**: 支持并发调用LLM，提高处理效率

## 📦 安装

```bash
# 进入项目目录
cd owasp_extractor

# 安装依赖
pip install -r requirements.txt
```

## 🚀 快速开始

### 1. 设置环境变量

```bash
# OpenAI
export OPENAI_API_KEY="your-api-key"

# 或 DeepSeek
export DEEPSEEK_API_KEY="your-api-key"

# 或 Anthropic
export ANTHROPIC_API_KEY="your-api-key"
```

### 2. 运行提取

```bash
# 使用 OpenAI (默认)
python -m owasp_extractor.cli ../cheatsheets -o output/rules.jsonl

# 使用 DeepSeek
python -m owasp_extractor.cli ../cheatsheets -o output/rules.jsonl \
    --provider deepseek --model deepseek-chat

# 使用本地 Ollama
python -m owasp_extractor.cli ../cheatsheets -o output/rules.jsonl \
    --provider ollama --model llama3.2

# 使用自定义 API 端点
python -m owasp_extractor.cli ../cheatsheets -o output/rules.jsonl \
    --provider custom --base-url "https://your-api.com/v1" --model "your-model"
```

### 3. 仅测试分片（不调用LLM）

```bash
# 查看所有文件的分片结果
python -m owasp_extractor.cli ../cheatsheets --chunk-only -v

# 测试单个文件
python -m owasp_extractor.cli ../cheatsheets --chunk-only --file SQL_Injection_Prevention_Cheat_Sheet.md -v
```

## 📊 输出格式

提取的安全规则为 JSONL 格式，每行一个 JSON 对象：

```json
{
  "rule_name": "Java中使用PreparedStatement防止SQL注入",
  "language": "Java",
  "vulnerability": "SQL Injection",
  "severity": "Critical",
  "rationale": "使用参数化查询可以确保用户输入被当作数据而不是SQL代码处理，数据库会自动区分代码和数据，从而阻止攻击者注入恶意SQL语句",
  "bad_code": "String query = \"SELECT * FROM users WHERE name = '\" + userInput + \"'\";\nStatement stmt = conn.createStatement();\nResultSet rs = stmt.executeQuery(query);",
  "good_code": "String query = \"SELECT * FROM users WHERE name = ?\";\nPreparedStatement pstmt = conn.prepareStatement(query);\npstmt.setString(1, userInput);\nResultSet rs = pstmt.executeQuery();",
  "description": "SQL注入防御: 在Java应用中使用PreparedStatement参数化查询代替字符串拼接，确保用户输入作为参数值而非SQL代码执行",
  "source_file": "SQL_Injection_Prevention_Cheat_Sheet.md",
  "section": "Defense Option 1: Prepared Statements",
  "tags": ["SQL注入", "Java", "PreparedStatement", "参数化查询", "数据库安全"]
}
```

## 🔧 命令行参数

```
使用: python -m owasp_extractor.cli <input_dir> [选项]

位置参数:
  input_dir              输入目录路径（cheatsheets文件夹）

输出配置:
  -o, --output FILE      输出文件路径 (默认: output/owasp_security_rules.jsonl)

LLM配置:
  --provider PROVIDER    LLM服务商: openai|azure|anthropic|deepseek|ollama|custom
  --model MODEL          模型名称 (默认根据provider自动选择)
  --api-key KEY          API密钥 (默认使用环境变量)
  --base-url URL         自定义API基础URL
  --temperature FLOAT    生成温度 (默认: 0.1)

并发配置:
  --max-concurrent N     最大并发请求数 (默认: 3)
  --retry N              失败重试次数 (默认: 3)

分片配置:
  --min-chunk N          最小分片长度 (默认: 100)
  --max-chunk N          最大分片长度 (默认: 8000)
  --require-code         只处理包含代码块的分片

调试选项:
  --chunk-only           仅执行分片，不调用LLM
  --file FILENAME        仅处理指定文件
  -v, --verbose          详细输出
```

## 📁 项目结构

```
owasp_extractor/
├── __init__.py          # 包初始化
├── models.py            # 数据模型定义
├── chunker.py           # Markdown分片器
├── prompts.py           # LLM提示词模板
├── llm_client.py        # LLM客户端封装
├── pipeline.py          # 提取流水线
├── cli.py               # 命令行工具
├── requirements.txt     # 依赖列表
└── README.md            # 说明文档
```

## 🔄 Python API 使用

```python
from owasp_extractor import OWASPExtractionPipeline, run_extraction

# 方式1: 使用便捷函数
rules = run_extraction(
    input_dir="./cheatsheets",
    output_file="output/rules.jsonl",
    provider="openai",
    model="gpt-4o-mini"
)

# 方式2: 使用Pipeline类（更多控制）
pipeline = OWASPExtractionPipeline(
    llm_provider="deepseek",
    llm_model="deepseek-chat",
    max_concurrent=5,
    chunk_min_length=200
)

rules = pipeline.run_sync(
    input_dir="./cheatsheets",
    output_file="output/rules.jsonl"
)

print(f"提取了 {len(rules)} 条安全规则")
```

## 🧩 分片策略

分片器采用以下策略确保提取质量：

1. **语义分割**: 以二级标题(##)为主要分割点
2. **上下文保留**: 保留父级标题链，确保理解上下文
3. **代码完整性**: 确保代码块不被截断
4. **质量过滤**: 过滤过短或纯链接/目录的分片

## 📝 提取Prompt设计

Prompt针对OWASP文档特点进行了优化：

1. **漏洞类型检测**: 根据文件名和内容自动识别漏洞类型
2. **代码识别**: 区分好代码(safe)和坏代码(vulnerable)示例
3. **缺失生成**: 如果只有好代码，会生成对应的坏代码示例
4. **中文输出**: 所有描述性字段使用中文

## 📈 向量化知识库构建

提取的数据可直接用于构建RAG系统：

```python
from langchain.embeddings import OpenAIEmbeddings
from langchain.vectorstores import Chroma
import json

# 加载规则
with open("output/rules.jsonl") as f:
    rules = [json.loads(line) for line in f]

# 构建文档
docs = []
for rule in rules:
    # 使用description作为检索内容
    content = f"{rule['rule_name']}\n{rule['description']}"
    docs.append({
        "content": content,
        "metadata": {
            "language": rule["language"],
            "vulnerability": rule["vulnerability"],
            "severity": rule["severity"]
        }
    })

# 向量化存储
embeddings = OpenAIEmbeddings()
vectorstore = Chroma.from_documents(docs, embeddings)
```

## 🔍 数据质量

每条规则都经过验证：

- 必填字段完整性检查
- 严重程度值有效性检查
- 描述长度检查（确保包含足够关键词）
- 标签数量检查（至少2个标签）

## ⚠️ 注意事项

1. **API成本**: 处理完整的CheatSheet目录会消耗大量Token，建议先用 `--chunk-only` 估算分片数量
2. **速率限制**: 适当设置 `--max-concurrent` 避免触发API速率限制
3. **网络稳定**: 确保网络连接稳定，流水线支持自动重试
4. **结果验证**: 建议人工抽查提取结果的质量

## 📄 License

MIT License
