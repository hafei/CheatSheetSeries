"""
OWASP 安全规则提取专用 Prompt 模板

设计用于从Markdown分片中提取结构化的安全编码规范
"""

SYSTEM_PROMPT = """你是一位资深的安全工程师和代码审计专家，专门从OWASP安全文档中提取结构化的安全编码规范。

## 你的任务
从提供的OWASP CheatSheet文档片段中，提取**可操作的安全编码规则**，用于构建代码安全知识库。

## 输出要求
1. **必须输出中文** - 所有描述性字段都用中文
2. **代码保持原样** - 代码示例保持原始语言，不翻译
3. **结构化输出** - 严格按照JSON格式输出
4. **高质量提取** - 只提取有实际代码指导意义的规则

## 提取重点
- 优先提取包含**代码示例**的安全规则
- 关注**漏洞防御方法**和**安全编码实践**
- 识别**好的代码模式**和**坏的代码模式**
- 标注适用的**编程语言**和**漏洞类型**

## 质量标准
- 规则必须具有**可操作性** - 开发者能直接应用
- 描述必须**简洁清晰** - 适合向量检索
- 代码示例必须**完整可用** - 能直接参考"""


EXTRACTION_PROMPT_TEMPLATE = """## 文档信息
- 文件名: {file_name}
- 文档标题: {doc_title}
- 章节: {section_title}
- 父级章节: {parent_sections}

## 文档内容
```markdown
{content}
```

## 提取任务
请从上述OWASP安全文档片段中提取安全编码规则。

### 输出格式
请输出一个JSON数组，每个元素代表一条安全规则:

```json
[
  {{
    "rule_name": "规则名称（中文，简洁描述防御措施）",
    "language": "编程语言（Java/Python/JavaScript/C#/PHP/Ruby/General等）",
    "vulnerability": "漏洞类型（SQL Injection/XSS/CSRF/Command Injection等）",
    "severity": "严重程度（Critical/High/Medium/Low）",
    "rationale": "防御原理（中文，解释为什么这样做能防御攻击）",
    "bad_code": "错误代码示例（如原文有则提取，无则根据场景生成典型错误写法，可为null）",
    "good_code": "安全代码示例（必填，展示正确的防御性编码）",
    "description": "向量检索摘要（中文，100-200字，包含关键词便于检索）",
    "tags": ["标签1", "标签2", "标签3"]
  }}
]
```

### 提取规则
1. **识别代码块**: 优先处理包含代码示例的内容
2. **判断语言**: 根据代码语法和上下文判断编程语言
3. **区分好坏代码**: 
   - 带"unsafe"、"vulnerable"、"bad"、"wrong"等描述的是坏代码
   - 带"safe"、"secure"、"correct"、"recommended"等描述的是好代码
4. **生成缺失示例**: 如果只有好代码，根据漏洞类型生成对应的坏代码示例
5. **漏洞分类**: 根据文档主题和内容准确分类漏洞类型
6. **标签生成**: 包含漏洞名、语言、防御技术、关键API等

### 特殊处理
- 如果片段**没有代码示例**但有重要的安全配置或概念，也要提取，language填"General"
- 如果片段是**纯理论介绍**或目录，返回空数组 `[]`
- 如果有**多种语言**的示例，为每种语言生成独立的规则

### 输出
直接输出JSON数组，不要包含markdown代码块标记:"""


ENHANCEMENT_PROMPT_TEMPLATE = """## 任务
请增强以下安全规则的内容，使其更完整、更有参考价值。

## 原始规则
```json
{original_rule}
```

## 增强要求
1. 如果 `bad_code` 为空，根据漏洞类型生成一个典型的错误代码示例
2. 优化 `description`，确保包含:
   - 漏洞的中文名称
   - 防御技术的关键词
   - 可能的攻击场景
3. 补充 `tags`，确保至少包含:
   - 漏洞类型（中英文）
   - 编程语言
   - 关键API或函数名
   - 防御技术名称
4. 验证 `severity` 是否合理

## 输出
输出增强后的完整JSON对象:"""


# 针对特定漏洞类型的专用提示
VULN_SPECIFIC_PROMPTS = {
    "sql_injection": """
## SQL注入防御重点
- 识别参数化查询（Prepared Statements）
- 识别ORM框架的安全用法
- 识别存储过程的安全实现
- 注意不同数据库的语法差异
""",
    
    "xss": """
## XSS防御重点
- 识别输出编码（HTML/JS/CSS/URL encoding）
- 识别安全的DOM操作方法
- 识别CSP配置
- 区分存储型/反射型/DOM型XSS的防御
""",
    
    "csrf": """
## CSRF防御重点
- 识别Token验证机制
- 识别SameSite Cookie设置
- 识别Referer/Origin检查
- 识别双重提交Cookie模式
""",
    
    "deserialization": """
## 反序列化防御重点
- 识别安全的反序列化配置
- 识别类型白名单实现
- 识别不同语言的反序列化API
- 注意Gadget链的概念
""",
    
    "command_injection": """
## 命令注入防御重点
- 识别安全的系统调用API
- 识别输入验证和过滤
- 识别参数化执行方式
- 注意不同OS的命令语法
""",
    
    "xxe": """
## XXE防御重点
- 识别XML解析器的安全配置
- 识别禁用外部实体的方法
- 识别不同语言/库的配置差异
- 注意DTD处理设置
"""
}


def get_extraction_prompt(
    file_name: str,
    doc_title: str,
    section_title: str,
    parent_sections: list,
    content: str,
    vuln_hint: str = None
) -> str:
    """
    生成提取prompt
    
    Args:
        file_name: 文件名
        doc_title: 文档标题
        section_title: 章节标题
        parent_sections: 父级章节列表
        content: 文档内容
        vuln_hint: 漏洞类型提示（可选）
        
    Returns:
        完整的prompt字符串
    """
    prompt = EXTRACTION_PROMPT_TEMPLATE.format(
        file_name=file_name,
        doc_title=doc_title,
        section_title=section_title,
        parent_sections=" > ".join(parent_sections) if parent_sections else "无",
        content=content
    )
    
    # 添加漏洞类型特定提示
    if vuln_hint and vuln_hint in VULN_SPECIFIC_PROMPTS:
        prompt = VULN_SPECIFIC_PROMPTS[vuln_hint] + "\n" + prompt
    
    return prompt


def get_system_prompt() -> str:
    """获取系统prompt"""
    return SYSTEM_PROMPT


def get_enhancement_prompt(original_rule: dict) -> str:
    """
    生成增强prompt
    
    Args:
        original_rule: 原始规则字典
        
    Returns:
        增强prompt字符串
    """
    import json
    return ENHANCEMENT_PROMPT_TEMPLATE.format(
        original_rule=json.dumps(original_rule, ensure_ascii=False, indent=2)
    )


def detect_vulnerability_type(file_name: str, content: str) -> str:
    """
    根据文件名和内容检测漏洞类型
    
    Args:
        file_name: 文件名
        content: 内容
        
    Returns:
        漏洞类型提示键
    """
    file_lower = file_name.lower()
    content_lower = content.lower()
    
    # 根据文件名检测
    if 'sql_injection' in file_lower or 'query_param' in file_lower:
        return 'sql_injection'
    elif 'xss' in file_lower or 'cross_site_scripting' in file_lower:
        return 'xss'
    elif 'csrf' in file_lower or 'cross_site_request' in file_lower:
        return 'csrf'
    elif 'deseriali' in file_lower:
        return 'deserialization'
    elif 'command_injection' in file_lower or 'os_command' in file_lower:
        return 'command_injection'
    elif 'xxe' in file_lower or 'xml_external' in file_lower:
        return 'xxe'
    
    # 根据内容检测
    if 'prepared statement' in content_lower or 'parameterized query' in content_lower:
        return 'sql_injection'
    elif 'innerhtml' in content_lower or 'document.write' in content_lower:
        return 'xss'
    elif 'csrf token' in content_lower or 'anti-forgery' in content_lower:
        return 'csrf'
    elif 'objectinputstream' in content_lower or 'pickle' in content_lower:
        return 'deserialization'
    elif 'runtime.exec' in content_lower or 'processbuilder' in content_lower:
        return 'command_injection'
    elif 'documentbuilderfactory' in content_lower and 'external' in content_lower:
        return 'xxe'
    
    return None


# 验证规则完整性
def validate_rule(rule: dict) -> tuple[bool, list[str]]:
    """
    验证规则的完整性
    
    Args:
        rule: 规则字典
        
    Returns:
        (是否有效, 问题列表)
    """
    issues = []
    
    required_fields = ['rule_name', 'language', 'vulnerability', 'severity', 
                       'rationale', 'good_code', 'description']
    
    for field in required_fields:
        if field not in rule or not rule[field]:
            issues.append(f"缺少必填字段: {field}")
    
    # 验证severity
    valid_severities = ['Critical', 'High', 'Medium', 'Low']
    if rule.get('severity') and rule['severity'] not in valid_severities:
        issues.append(f"无效的severity值: {rule['severity']}")
    
    # 验证description长度
    if rule.get('description') and len(rule['description']) < 20:
        issues.append("description过短，应包含更多关键词")
    
    # 验证tags
    if not rule.get('tags') or len(rule.get('tags', [])) < 2:
        issues.append("tags应至少包含2个标签")
    
    return len(issues) == 0, issues
