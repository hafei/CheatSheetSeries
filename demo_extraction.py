#!/usr/bin/env python3
"""
OWASP 安全规则提取示例脚本

演示如何使用 owasp_extractor 提取安全规则
"""
import os
import sys
import json
from pathlib import Path

# 添加项目路径
sys.path.insert(0, str(Path(__file__).parent))

from owasp_extractor import (
    OWASPExtractionPipeline, 
    run_extraction,
    MarkdownChunker
)


def demo_chunking():
    """演示分片功能"""
    print("\n" + "=" * 60)
    print("📚 演示1: Markdown 分片")
    print("=" * 60)
    
    # 创建分片器
    chunker = MarkdownChunker(
        min_chunk_length=100,
        max_chunk_length=8000,
        include_code_required=False
    )
    
    # 分片单个文件
    cheatsheets_dir = Path(__file__).parent / "cheatsheets"
    test_file = cheatsheets_dir / "SQL_Injection_Prevention_Cheat_Sheet.md"
    
    if test_file.exists():
        sections = chunker.parse_file(test_file)
        
        print(f"\n文件: {test_file.name}")
        print(f"分片数: {len(sections)}")
        
        for i, section in enumerate(sections):
            print(f"\n[{i+1}] {section.section_title}")
            print(f"    层级: H{section.section_level}")
            print(f"    父级: {' > '.join(section.parent_sections) if section.parent_sections else '无'}")
            print(f"    内容长度: {len(section.content)} 字符")
            print(f"    代码块: {len(section.code_blocks)} 个")
            
            # 显示代码块语言
            if section.code_blocks:
                langs = [cb.language for cb in section.code_blocks]
                print(f"    代码语言: {', '.join(langs)}")
    else:
        print(f"⚠️ 文件不存在: {test_file}")


def demo_extraction_single_file():
    """演示单文件提取（需要API Key）"""
    print("\n" + "=" * 60)
    print("📝 演示2: 单文件安全规则提取")
    print("=" * 60)
    
    # 检查API Key
    api_key = os.environ.get("OPENAI_API_KEY") or os.environ.get("DEEPSEEK_API_KEY")
    
    if not api_key:
        print("\n⚠️ 未设置 API Key，跳过此演示")
        print("请设置环境变量: OPENAI_API_KEY 或 DEEPSEEK_API_KEY")
        return
    
    # 确定使用的provider
    if os.environ.get("DEEPSEEK_API_KEY"):
        provider = "deepseek"
        model = "deepseek-chat"
    else:
        provider = "openai"
        model = "gpt-4o-mini"
    
    print(f"\n使用 {provider} ({model}) 进行提取...")
    
    # 创建流水线
    pipeline = OWASPExtractionPipeline(
        llm_provider=provider,
        llm_model=model,
        max_concurrent=2
    )
    
    # 只处理一个文件
    cheatsheets_dir = Path(__file__).parent / "cheatsheets"
    output_file = Path(__file__).parent / "output" / "demo_rules.json"
    
    rules = pipeline.run_sync(
        str(cheatsheets_dir),
        str(output_file),
        file_pattern="SQL_Injection_Prevention_Cheat_Sheet.md"
    )
    
    print(f"\n✅ 提取完成，共 {len(rules)} 条规则")
    
    # 展示第一条规则
    if rules:
        print("\n📋 规则示例:")
        print(json.dumps(rules[0], ensure_ascii=False, indent=2))


def demo_output_format():
    """演示输出数据结构"""
    print("\n" + "=" * 60)
    print("📊 演示3: 输出数据结构")
    print("=" * 60)
    
    # 示例规则
    example_rule = {
        "rule_name": "Java中使用PreparedStatement防止SQL注入",
        "language": "Java",
        "vulnerability": "SQL Injection",
        "severity": "Critical",
        "rationale": "使用参数化查询可以确保用户输入被当作数据而不是SQL代码处理，数据库会自动区分代码和数据，从而阻止攻击者注入恶意SQL语句。PreparedStatement会对参数进行预编译和转义，即使输入包含SQL关键字或特殊字符也不会被解释为SQL命令。",
        "bad_code": """// 危险的代码 - 直接拼接SQL
String query = "SELECT * FROM users WHERE name = '" + userInput + "'";
Statement stmt = conn.createStatement();
ResultSet rs = stmt.executeQuery(query);
// 攻击者可以输入: ' OR '1'='1
// 导致查询变成: SELECT * FROM users WHERE name = '' OR '1'='1'""",
        "good_code": """// 安全的代码 - 使用参数化查询
String query = "SELECT * FROM users WHERE name = ?";
PreparedStatement pstmt = conn.prepareStatement(query);
pstmt.setString(1, userInput);
ResultSet rs = pstmt.executeQuery();
// 用户输入会被安全地作为参数值处理""",
        "description": "SQL注入防御：在Java应用中使用PreparedStatement参数化查询代替字符串拼接。参数化查询通过预编译SQL语句，将用户输入作为参数值而非SQL代码执行，有效防止SQL注入攻击。适用于所有数据库操作场景，是防御SQL注入的首选方案。",
        "source_file": "SQL_Injection_Prevention_Cheat_Sheet.md",
        "section": "Defense Option 1: Prepared Statements",
        "tags": [
            "SQL注入",
            "SQL Injection", 
            "Java",
            "PreparedStatement",
            "参数化查询",
            "数据库安全",
            "JDBC"
        ]
    }
    
    print("\n📌 OWASPSecurityRule 数据结构:")
    print(json.dumps(example_rule, ensure_ascii=False, indent=2))
    
    print("\n📌 各字段说明:")
    fields = [
        ("rule_name", "规则名称（中文）"),
        ("language", "编程语言"),
        ("vulnerability", "漏洞类型"),
        ("severity", "严重程度: Critical/High/Medium/Low"),
        ("rationale", "防御原理（为什么有效）"),
        ("bad_code", "错误代码示例"),
        ("good_code", "安全代码示例"),
        ("description", "向量检索摘要"),
        ("source_file", "来源文件"),
        ("section", "来源章节"),
        ("tags", "检索标签"),
    ]
    
    for field, desc in fields:
        print(f"  • {field}: {desc}")


def main():
    print("🔐 OWASP 安全规则提取器 - 功能演示")
    
    # 演示1: 分片
    demo_chunking()
    
    # 演示2: 输出格式
    demo_output_format()
    
    # 演示3: 实际提取（需要API Key）
    # demo_extraction_single_file()
    
    print("\n" + "=" * 60)
    print("✅ 演示完成!")
    print("\n要运行完整提取，请使用命令:")
    print("  python -m owasp_extractor.cli ./cheatsheets -o output/rules.jsonl")
    print("=" * 60)


if __name__ == "__main__":
    main()
