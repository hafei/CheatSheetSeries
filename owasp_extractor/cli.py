#!/usr/bin/env python3
"""
OWASP CheatSheet 安全规则提取器 - 命令行工具

使用方法:
    # 使用OpenAI
    python -m owasp_extractor.cli ./cheatsheets -o output/rules.jsonl
    
    # 使用DeepSeek
    python -m owasp_extractor.cli ./cheatsheets -o output/rules.jsonl --provider deepseek --model deepseek-chat
    
    # 使用本地Ollama
    python -m owasp_extractor.cli ./cheatsheets -o output/rules.jsonl --provider ollama --model llama3.2
    
    # 仅测试分片（不调用LLM）
    python -m owasp_extractor.cli ./cheatsheets --chunk-only
"""
import argparse
import sys
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(
        description="OWASP CheatSheet 安全规则提取器",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s ./cheatsheets -o output/rules.jsonl
  %(prog)s ./cheatsheets --provider deepseek --model deepseek-chat
  %(prog)s ./cheatsheets --chunk-only -v
        """
    )
    
    # 必选参数
    parser.add_argument(
        "input_dir",
        type=str,
        help="输入目录路径（cheatsheets文件夹）"
    )
    
    # 输出配置
    parser.add_argument(
        "-o", "--output",
        type=str,
        default="output/owasp_security_rules.jsonl",
        help="输出文件路径 (默认: output/owasp_security_rules.jsonl)"
    )
    
    # LLM配置
    parser.add_argument(
        "--provider",
        type=str,
        default="openai",
        choices=["openai", "azure", "anthropic", "deepseek", "ollama", "custom"],
        help="LLM服务商 (默认: openai)"
    )
    parser.add_argument(
        "--model",
        type=str,
        default=None,
        help="模型名称 (默认根据provider自动选择)"
    )
    parser.add_argument(
        "--api-key",
        type=str,
        default=None,
        help="API密钥 (默认使用环境变量)"
    )
    parser.add_argument(
        "--base-url",
        type=str,
        default=None,
        help="自定义API基础URL"
    )
    parser.add_argument(
        "--temperature",
        type=float,
        default=0.1,
        help="生成温度 (默认: 0.1)"
    )
    
    # 并发配置
    parser.add_argument(
        "--max-concurrent",
        type=int,
        default=3,
        help="最大并发请求数 (默认: 3)"
    )
    parser.add_argument(
        "--retry",
        type=int,
        default=3,
        help="失败重试次数 (默认: 3)"
    )
    
    # 分片配置
    parser.add_argument(
        "--min-chunk",
        type=int,
        default=100,
        help="最小分片长度 (默认: 100)"
    )
    parser.add_argument(
        "--max-chunk",
        type=int,
        default=8000,
        help="最大分片长度 (默认: 8000)"
    )
    parser.add_argument(
        "--require-code",
        action="store_true",
        help="只处理包含代码块的分片"
    )
    
    # 调试选项
    parser.add_argument(
        "--chunk-only",
        action="store_true",
        help="仅执行分片，不调用LLM（用于测试）"
    )
    parser.add_argument(
        "--file",
        type=str,
        default=None,
        help="仅处理指定文件"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="详细输出"
    )
    
    args = parser.parse_args()
    
    # 检查输入目录
    input_path = Path(args.input_dir)
    if not input_path.exists():
        print(f"❌ 错误: 输入目录不存在: {args.input_dir}")
        sys.exit(1)
    
    # 仅分片模式
    if args.chunk_only:
        run_chunk_only(args)
        return
    
    # 完整提取流程
    run_extraction_pipeline(args)


def run_chunk_only(args):
    """仅执行分片测试"""
    from .chunker import MarkdownChunker
    
    print("🔍 分片测试模式")
    print("=" * 60)
    
    chunker = MarkdownChunker(
        min_chunk_length=args.min_chunk,
        max_chunk_length=args.max_chunk,
        include_code_required=args.require_code
    )
    
    input_path = Path(args.input_dir)
    
    # 确定要处理的文件
    if args.file:
        files = [input_path / args.file]
    else:
        files = list(input_path.glob("*.md"))
    
    total_chunks = 0
    total_code_blocks = 0
    
    for file_path in sorted(files):
        if not file_path.exists():
            print(f"⚠️  文件不存在: {file_path}")
            continue
            
        sections = chunker.parse_file(file_path)
        code_blocks = sum(len(s.code_blocks) for s in sections)
        
        print(f"\n📄 {file_path.name}")
        print(f"   分片数: {len(sections)}, 代码块: {code_blocks}")
        
        if args.verbose:
            for i, section in enumerate(sections):
                print(f"   [{i+1}] {section.section_title}")
                print(f"       层级: H{section.section_level}, 长度: {len(section.content)}")
                if section.code_blocks:
                    langs = [cb.language for cb in section.code_blocks]
                    print(f"       代码: {', '.join(langs)}")
        
        total_chunks += len(sections)
        total_code_blocks += code_blocks
    
    print("\n" + "=" * 60)
    print(f"📊 统计: {len(files)} 文件, {total_chunks} 分片, {total_code_blocks} 代码块")


def run_extraction_pipeline(args):
    """运行完整提取流程"""
    from .pipeline import OWASPExtractionPipeline
    from .config_loader import load_config, ConfigError
    
    print("🚀 OWASP安全规则提取器")
    print("=" * 60)
    print(f"   输入目录: {args.input_dir}")
    print(f"   输出文件: {args.output}")
    print(f"   LLM服务商: {args.provider}")
    print(f"   模型: {args.model or '(自动选择)'}")
    print(f"   并发数: {args.max_concurrent}")
    print("=" * 60)
    
    # 尝试从配置文件加载（如果存在），CLI参数优先覆盖配置文件中的值
    cfg_obj = None
    try:
        cfg_obj = load_config()
    except ConfigError as e:
        if args.verbose:
            print(f"⚠️ 配置加载警告: {e}")

    if cfg_obj is not None:
        # 将配置对象转换为构造参数，并用CLI参数覆盖显式提供的值
        pipeline_kwargs = {
            'llm_provider': cfg_obj.llm_provider,
            'llm_model': cfg_obj.llm_model,
            'llm_api_key': cfg_obj.llm_api_key,
            'llm_base_url': cfg_obj.llm_base_url,
            'llm_temperature': cfg_obj.llm_temperature,
            'llm_max_tokens': cfg_obj.llm_max_tokens,
            'chunk_min_length': cfg_obj.chunk_min_length,
            'chunk_max_length': cfg_obj.chunk_max_length,
            'include_code_required': cfg_obj.include_code_blocks,
            'max_concurrent': cfg_obj.max_concurrent,
            'retry_count': cfg_obj.retry_count,
            'retry_delay': cfg_obj.retry_delay,
            'output_dir': cfg_obj.output_dir,
        }

        # CLI覆盖规则（仅在与默认不同或显式提供时覆盖）
        if args.provider and args.provider != 'openai':
            pipeline_kwargs['llm_provider'] = args.provider
        if args.model:
            pipeline_kwargs['llm_model'] = args.model
        if args.api_key:
            pipeline_kwargs['llm_api_key'] = args.api_key
        if args.base_url:
            pipeline_kwargs['llm_base_url'] = args.base_url
        if args.temperature is not None and args.temperature != 0.1:
            pipeline_kwargs['llm_temperature'] = args.temperature
        if args.min_chunk is not None and args.min_chunk != 100:
            pipeline_kwargs['chunk_min_length'] = args.min_chunk
        if args.max_chunk is not None and args.max_chunk != 8000:
            pipeline_kwargs['chunk_max_length'] = args.max_chunk
        if args.require_code:
            pipeline_kwargs['include_code_required'] = True
        if args.max_concurrent is not None and args.max_concurrent != 3:
            pipeline_kwargs['max_concurrent'] = args.max_concurrent
        if args.retry is not None and args.retry != 3:
            pipeline_kwargs['retry_count'] = args.retry

        pipeline = OWASPExtractionPipeline(**pipeline_kwargs)
    else:
        # 未找到配置文件，使用CLI参数构建流水线
        pipeline = OWASPExtractionPipeline(
            llm_provider=args.provider,
            llm_model=args.model,
            llm_api_key=args.api_key,
            llm_base_url=args.base_url,
            llm_temperature=args.temperature,
            chunk_min_length=args.min_chunk,
            chunk_max_length=args.max_chunk,
            include_code_required=args.require_code,
            max_concurrent=args.max_concurrent,
            retry_count=args.retry,
        )
    
    # 确定文件模式
    if args.file:
        file_pattern = args.file
    else:
        file_pattern = "*.md"
    
    # 运行
    try:
        rules = pipeline.run_sync(
            args.input_dir,
            args.output,
            file_pattern
        )
        print(f"\n✅ 完成! 共提取 {len(rules)} 条安全规则")
        
    except KeyboardInterrupt:
        print("\n⚠️  用户中断")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ 错误: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
