"""
OWASP 安全规则提取流水线

主流水线模块，整合分片、LLM调用和结果处理
"""
import json
import asyncio
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Optional, Dict, Any
from dataclasses import dataclass
import re

from .chunker import MarkdownChunker, MarkdownSection
from .prompts import (
    get_system_prompt, 
    get_extraction_prompt, 
    detect_vulnerability_type,
    validate_rule
)
from .llm_client import create_llm_client
from .config_loader import load_config, ConfigError
from .models import PipelineConfig


# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class PipelineStats:
    """流水线统计"""
    total_files: int = 0
    processed_files: int = 0
    total_chunks: int = 0
    processed_chunks: int = 0
    total_rules: int = 0
    failed_chunks: int = 0
    total_tokens: int = 0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    
    @property
    def duration_seconds(self) -> float:
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0


class OWASPExtractionPipeline:
    """OWASP安全规则提取流水线
    
    主要功能:
    1. 扫描Markdown文件
    2. 智能分片
    3. 调用LLM提取规则
    4. 验证和存储结果
    """
    
    def __init__(
        self,
        # LLM配置
        llm_provider: str = "openai",
        llm_model: str = "gpt-4o-mini",
        llm_api_key: Optional[str] = None,
        llm_base_url: Optional[str] = None,
        llm_temperature: float = 0.1,
        llm_max_tokens: int = 4096,
        # 分片配置
        chunk_min_length: int = 100,
        chunk_max_length: int = 8000,
        include_code_required: bool = False,
        # 运行配置
        max_concurrent: int = 3,
        retry_count: int = 3,
        retry_delay: float = 1.0,
        # 输出配置
        output_dir: str = "./output",
    ):
        # 创建LLM客户端
        self.llm_client = create_llm_client(
            provider=llm_provider,
            api_key=llm_api_key,
            base_url=llm_base_url,
            model=llm_model,
            temperature=llm_temperature,
            max_tokens=llm_max_tokens
        )
        
        # 创建分片器
        self.chunker = MarkdownChunker(
            min_chunk_length=chunk_min_length,
            max_chunk_length=chunk_max_length,
            include_code_required=include_code_required
        )
        
        # 配置
        self.max_concurrent = max_concurrent
        self.retry_count = retry_count
        self.retry_delay = retry_delay
        self.output_dir = Path(output_dir)
        
        # 统计
        self.stats = PipelineStats()
        
        # 信号量控制并发
        self._semaphore: Optional[asyncio.Semaphore] = None
    
    @classmethod
    def from_config(cls, cfg: PipelineConfig) -> "OWASPExtractionPipeline":
        """Construct pipeline from a PipelineConfig instance."""
        return cls(
            llm_provider=cfg.llm_provider,
            llm_model=cfg.llm_model,
            llm_api_key=cfg.llm_api_key,
            llm_base_url=cfg.llm_base_url,
            llm_temperature=cfg.llm_temperature,
            llm_max_tokens=cfg.llm_max_tokens,
            chunk_min_length=cfg.chunk_min_length,
            chunk_max_length=cfg.chunk_max_length,
            include_code_required=cfg.include_code_blocks,
            max_concurrent=cfg.max_concurrent,
            retry_count=cfg.retry_count,
            retry_delay=cfg.retry_delay,
            output_dir=cfg.output_dir,
        )

    def scan_files(self, input_dir: Path, pattern: str = "*.md") -> List[Path]:
        """扫描目录下的Markdown文件"""
        files = list(input_dir.glob(pattern))
        self.stats.total_files = len(files)
        logger.info(f"扫描到 {len(files)} 个Markdown文件")
        return sorted(files)
    
    def chunk_file(self, file_path: Path) -> List[MarkdownSection]:
        """对单个文件进行分片"""
        try:
            sections = self.chunker.parse_file(file_path)
            logger.info(f"文件 {file_path.name} 分片: {len(sections)} 个")
            return sections
        except Exception as e:
            logger.error(f"分片失败 {file_path}: {e}")
            return []
    
    async def extract_rules_from_chunk(
        self, 
        section: MarkdownSection
    ) -> List[Dict[str, Any]]:
        """从单个分片提取安全规则"""
        # 检测漏洞类型
        vuln_hint = detect_vulnerability_type(
            section.file_name, 
            section.content
        )
        
        # 如果分片内容过大，截断首尾以避免模型输出被截断为空
        MAX_PROMPT_CONTENT = 80000
        content_to_use = section.content
        if len(section.content) > MAX_PROMPT_CONTENT:
            head = section.content[:1500]
            tail = section.content[-1500:]
            content_to_use = head + "\n\n... （中间被截断，为了确保模型能返回完整JSON而省略） ...\n\n" + tail
            logger.info(f"分片内容过长，已截断 file={section.file_name} section={section.section_title}")

        # 构建prompt
        prompt = get_extraction_prompt(
            file_name=section.file_name,
            doc_title=section.title,
            section_title=section.section_title,
            parent_sections=section.parent_sections,
            content=content_to_use,
            vuln_hint=vuln_hint
        )
        
        messages = [
            {"role": "system", "content": get_system_prompt()},
            {"role": "user", "content": prompt}
        ]
        
        # 重试逻辑
        last_error = None
        for attempt in range(self.retry_count):
            try:
                async with self._semaphore:
                    response = await self.llm_client.chat(messages)
                
                # 更新token统计
                self.stats.total_tokens += response.usage.get("total_tokens", 0)
                # 如果返回内容为空，记录并将 raw_response 写入 debug 文件，然后触发重试
                if not (response.content and response.content.strip()):
                    try:
                        log_dir = self.output_dir if hasattr(self, 'output_dir') else Path('./output')
                        log_dir.mkdir(parents=True, exist_ok=True)
                        debug_file = log_dir / 'llm_raw_response_debug.jsonl'
                        debug_obj = {
                            'timestamp': datetime.utcnow().isoformat() + 'Z',
                            'source_file': section.file_name,
                            'section': section.section_title,
                            'raw_response': getattr(response, 'raw_response', None)
                        }
                        with open(debug_file, 'a', encoding='utf-8') as df:
                            df.write(json.dumps(debug_obj, ensure_ascii=False) + '\n')
                    except Exception:
                        pass

                    raise ValueError('Empty LLM response content')

                # 解析JSON响应（并记录原始响应以便调试）
                rules = self._parse_json_response(response.content, section, raw_response=getattr(response, 'raw_response', None))
                
                # 为每个规则添加来源信息
                for rule in rules:
                    rule["source_file"] = section.file_name
                    rule["section"] = section.section_title
                    
                    # 验证规则
                    is_valid, issues = validate_rule(rule)
                    if not is_valid:
                        logger.warning(f"规则验证问题: {issues}")
                
                return rules
                
            except Exception as e:
                last_error = e
                logger.warning(f"提取失败 (尝试 {attempt + 1}/{self.retry_count}): {e}")
                if attempt < self.retry_count - 1:
                    await asyncio.sleep(self.retry_delay * (attempt + 1))
        
        logger.error(f"提取最终失败: {section.section_title}, 错误: {last_error}")
        self.stats.failed_chunks += 1
        return []
    
    def _parse_json_response(self, content: str, section: Optional[MarkdownSection] = None, raw_response: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """解析LLM返回的JSON"""
        # 清理响应内容
        content = content.strip()
        
        # 移除可能的markdown代码块标记
        if content.startswith("```"):
            # 找到第一个换行
            first_newline = content.find('\n')
            if first_newline != -1:
                content = content[first_newline + 1:]
            # 移除结尾的```
            if content.endswith("```"):
                content = content[:-3]
            content = content.strip()
        
        # 尝试解析JSON
        try:
            result = json.loads(content)
            if isinstance(result, list):
                return result
            elif isinstance(result, dict):
                # 如果返回的是包含rules的对象
                if "rules" in result:
                    return result["rules"]
                return [result]
            return []
        except json.JSONDecodeError as e:
            # 将原始响应追加到调试日志，包含来源信息
            try:
                log_dir = self.output_dir if hasattr(self, 'output_dir') else Path('./output')
                log_dir.mkdir(parents=True, exist_ok=True)
                # 原始文本日志（人类可读）
                log_file = log_dir / 'llm_raw_responses.log'
                with open(log_file, 'a', encoding='utf-8') as lf:
                    header = f"\n--- {datetime.utcnow().isoformat()}Z"
                    if section:
                        header += f" | file={section.file_name} | section={section.section_title}"
                    lf.write(header + '\n')
                    lf.write(content + '\n')

                # 结构化原始响应（JSONL），如果上层提供了 raw_response，则写入以便后续分析
                if raw_response is not None:
                    debug_file = log_dir / 'llm_raw_response_debug.jsonl'
                    # 保存到 jsonl，每行一个对象，添加元信息
                    debug_obj = {
                        'timestamp': datetime.utcnow().isoformat() + 'Z',
                        'source_file': section.file_name if section else None,
                        'section': section.section_title if section else None,
                        'raw_response': raw_response
                    }
                    with open(debug_file, 'a', encoding='utf-8') as df:
                        df.write(json.dumps(debug_obj, ensure_ascii=False) + '\n')
            except Exception:
                pass

            # 如果 response 的 raw_response 有结构信息，也将其存为 jsonl 以便分析（避免覆盖）
            try:
                # raw_response 可在上层 llm_client 中通过 response.raw_response 传入
                # 但此处只有 content 字符串可用——尝试从调用栈中寻找 raw_response 不现实
                # 因此，上层在调用 _parse_json_response 时应传入原始 LLMResponse 对象或字典
                # 作为补充，这里仅写入 content 已记录。如果上层传入了额外属性，可另行记录。
                pass
            except Exception:
                pass

            # 尝试修复常见JSON问题的多种策略
            # 1) 提取最像JSON的数组或对象
            try:
                match = re.search(r'\[.*\]', content, flags=re.S)
                if match:
                    candidate = match.group()
                    # 移除尾随逗号
                    candidate = re.sub(r',\s*\]', ']', candidate)
                    return json.loads(candidate)
            except Exception:
                pass

            try:
                match = re.search(r'\{.*\}', content, flags=re.S)
                if match:
                    candidate = match.group()
                    candidate = re.sub(r',\s*\}', '}', candidate)
                    # 将单引号替换为双引号（谨慎）
                    candidate2 = candidate.replace("'", '"')
                    try:
                        return json.loads(candidate2)
                    except Exception:
                        return json.loads(candidate)
            except Exception:
                pass

            # 2) 替换常见的错误（尾随逗号、单引号）并重试
            try:
                s = content
                s = re.sub(r',\s*([\]}])', r'\1', s)
                s = s.replace("'", '"')
                return json.loads(s)
            except Exception:
                pass

            logger.error(f"JSON解析失败: {e}")
            logger.debug(f"原始内容前500字: {content[:500]}...")
            return []
    
    async def process_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """处理单个文件"""
        all_rules = []
        
        # 分片
        sections = self.chunk_file(file_path)
        self.stats.total_chunks += len(sections)
        
        # 创建提取任务
        tasks = []
        for section in sections:
            task = self.extract_rules_from_chunk(section)
            tasks.append(task)
        
        # 并发执行
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"任务异常: {result}")
                self.stats.failed_chunks += 1
            elif isinstance(result, list):
                all_rules.extend(result)
                self.stats.processed_chunks += 1
        
        self.stats.processed_files += 1
        self.stats.total_rules += len(all_rules)
        
        logger.info(f"文件处理完成: {file_path.name}, 提取规则: {len(all_rules)} 条")
        return all_rules
    
    async def run(
        self, 
        input_dir: str,
        output_file: Optional[str] = None,
        file_pattern: str = "*.md"
    ) -> List[Dict[str, Any]]:
        """
        运行提取流水线
        
        Args:
            input_dir: 输入目录（cheatsheets文件夹）
            output_file: 输出文件路径
            file_pattern: 文件匹配模式
            
        Returns:
            提取的所有安全规则
        """
        self.stats = PipelineStats()
        self.stats.start_time = datetime.now()
        self._semaphore = asyncio.Semaphore(self.max_concurrent)
        
        input_path = Path(input_dir)
        if not input_path.exists():
            raise FileNotFoundError(f"输入目录不存在: {input_dir}")
        
        # 扫描文件
        files = self.scan_files(input_path, file_pattern)
        
        all_rules = []
        
        # 处理每个文件
        for file_path in files:
            try:
                rules = await self.process_file(file_path)
                all_rules.extend(rules)

                # 中间保存（防止中断丢失）: 每处理完一个文件就保存一次
                if output_file:
                    self._save_intermediate(all_rules, output_file)
                    
            except Exception as e:
                logger.error(f"处理文件失败 {file_path}: {e}")
        
        self.stats.end_time = datetime.now()
        
        # 最终保存
        if output_file:
            self._save_results(all_rules, output_file)
        
        # 打印统计
        self._print_stats()
        
        return all_rules
    
    def run_sync(
        self, 
        input_dir: str,
        output_file: Optional[str] = None,
        file_pattern: str = "*.md"
    ) -> List[Dict[str, Any]]:
        """同步运行流水线"""
        return asyncio.run(self.run(input_dir, output_file, file_pattern))
    
    def _save_intermediate(self, rules: List[Dict], output_file: str):
        """保存中间结果"""
        try:
            temp_file = output_file + ".tmp"
            self._save_results(rules, temp_file)
        except Exception as e:
            logger.warning(f"中间保存失败: {e}")
    
    def _save_results(self, rules: List[Dict], output_file: str):
        """保存最终结果"""
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # 根据扩展名选择格式
        if output_file.endswith('.jsonl'):
            with open(output_path, 'w', encoding='utf-8') as f:
                for rule in rules:
                    f.write(json.dumps(rule, ensure_ascii=False) + '\n')
        else:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(rules, f, ensure_ascii=False, indent=2)
        
        logger.info(f"结果已保存: {output_path} ({len(rules)} 条规则)")
    
    def _print_stats(self):
        """打印统计信息"""
        stats = self.stats
        print("\n" + "=" * 60)
        print("📊 流水线运行统计")
        print("=" * 60)
        print(f"  文件处理: {stats.processed_files}/{stats.total_files}")
        print(f"  分片处理: {stats.processed_chunks}/{stats.total_chunks}")
        print(f"  失败分片: {stats.failed_chunks}")
        print(f"  提取规则: {stats.total_rules} 条")
        print(f"  Token消耗: {stats.total_tokens:,}")
        print(f"  运行时长: {stats.duration_seconds:.1f} 秒")
        print("=" * 60 + "\n")


def run_extraction(
    input_dir: str,
    output_file: str,
    provider: str = "openai",
    model: str = "gpt-4o-mini",
    api_key: Optional[str] = None,
    base_url: Optional[str] = None,
    max_concurrent: int = 3,
    **kwargs
) -> List[Dict[str, Any]]:
    """
    便捷函数：运行OWASP规则提取
    
    Args:
        input_dir: cheatsheets目录路径
        output_file: 输出文件路径
        provider: LLM服务商
        model: 模型名称
        api_key: API密钥（可选，优先使用环境变量）
        base_url: 自定义API地址（可选）
        max_concurrent: 最大并发数
        
    Returns:
        提取的规则列表
    """
    # If a config path is provided in kwargs or via env, prefer that configuration
    config_path = kwargs.pop("config_path", None)
    cfg_obj = None
    if config_path:
        try:
            cfg_obj = load_config(config_path)
        except ConfigError as e:
            logger.error(f"配置加载失败: {e}")
            raise

    if cfg_obj is not None:
        pipeline = OWASPExtractionPipeline.from_config(cfg_obj)
    else:
        pipeline = OWASPExtractionPipeline(
            llm_provider=provider,
            llm_model=model,
            llm_api_key=api_key,
            llm_base_url=base_url,
            max_concurrent=max_concurrent,
            **kwargs
        )

    return pipeline.run_sync(input_dir, output_file)
