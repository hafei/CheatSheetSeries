"""
Markdown 分片器

负责将OWASP CheatSheet的Markdown文件智能分片
"""
import re
from pathlib import Path
from typing import List, Tuple, Optional, Generator
from dataclasses import dataclass, field


@dataclass
class CodeBlock:
    """代码块结构"""
    language: str
    code: str
    start_line: int
    end_line: int


@dataclass
class MarkdownSection:
    """Markdown章节结构"""
    file_name: str
    title: str
    section_title: str
    section_level: int
    content: str = ""
    code_blocks: List[CodeBlock] = field(default_factory=list)
    parent_sections: List[str] = field(default_factory=list)
    start_line: int = 0
    end_line: int = 0


class MarkdownChunker:
    """Markdown智能分片器
    
    分片策略:
    1. 按照标题层级(##, ###)进行语义分割
    2. 保持代码块的完整性
    3. 保留上下文关系(父级标题链)
    4. 过滤过短或无实质内容的分片
    """
    
    # 标题正则
    HEADING_PATTERN = re.compile(r'^(#{1,6})\s+(.+)$', re.MULTILINE)
    # 代码块正则
    CODE_BLOCK_PATTERN = re.compile(
        r'```(\w*)\n(.*?)```',
        re.DOTALL
    )
    # 行内代码正则
    INLINE_CODE_PATTERN = re.compile(r'`[^`]+`')
    
    def __init__(
        self,
        min_chunk_length: int = 100,
        max_chunk_length: int = 8000,
        target_section_level: int = 2,
        include_code_required: bool = False
    ):
        """
        初始化分片器
        
        Args:
            min_chunk_length: 最小分片字符数
            max_chunk_length: 最大分片字符数
            target_section_level: 目标分割层级 (2 = ##)
            include_code_required: 是否要求必须包含代码块
        """
        self.min_chunk_length = min_chunk_length
        self.max_chunk_length = max_chunk_length
        self.target_section_level = target_section_level
        self.include_code_required = include_code_required
    
    def parse_file(self, file_path: Path) -> List[MarkdownSection]:
        """
        解析Markdown文件并分片
        
        Args:
            file_path: Markdown文件路径
            
        Returns:
            分片列表
        """
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        return self.parse_content(content, file_path.name)
    
    def parse_content(self, content: str, file_name: str) -> List[MarkdownSection]:
        """
        解析Markdown内容并分片
        
        Args:
            content: Markdown文本内容
            file_name: 文件名
            
        Returns:
            分片列表
        """
        lines = content.split('\n')
        sections: List[MarkdownSection] = []
        
        # 获取文档主标题
        main_title = self._extract_main_title(lines)
        
        # 构建章节树
        section_tree = self._build_section_tree(lines, file_name, main_title)
        
        # 转换为平坦的分片列表
        for section in section_tree:
            if self._is_valid_section(section):
                sections.append(section)
        
        return sections
    
    def _extract_main_title(self, lines: List[str]) -> str:
        """提取文档主标题"""
        for line in lines:
            match = self.HEADING_PATTERN.match(line)
            if match and len(match.group(1)) == 1:
                return match.group(2).strip()
        return "Unknown"
    
    def _build_section_tree(
        self, 
        lines: List[str], 
        file_name: str,
        main_title: str
    ) -> List[MarkdownSection]:
        """
        构建章节树
        
        智能分片策略:
        - 以二级标题(##)为主要分割点
        - 三级及以下标题(###, ####)作为子内容合并
        - 保持代码块完整性
        """
        sections = []
        current_section: Optional[MarkdownSection] = None
        parent_stack: List[Tuple[int, str]] = []  # (level, title)
        
        current_content_lines: List[str] = []
        in_code_block = False
        code_block_start = 0
        code_block_lang = ""
        code_block_content: List[str] = []
        
        for i, line in enumerate(lines):
            # 检测代码块边界
            if line.strip().startswith('```'):
                if not in_code_block:
                    # 开始代码块
                    in_code_block = True
                    code_block_start = i
                    code_block_lang = line.strip()[3:].strip()
                    code_block_content = []
                else:
                    # 结束代码块
                    in_code_block = False
                    if current_section:
                        current_section.code_blocks.append(
                            CodeBlock(
                                language=code_block_lang,
                                code='\n'.join(code_block_content),
                                start_line=code_block_start,
                                end_line=i
                            )
                        )
                current_content_lines.append(line)
                continue
            
            if in_code_block:
                code_block_content.append(line)
                current_content_lines.append(line)
                continue
            
            # 检测标题
            match = self.HEADING_PATTERN.match(line)
            if match:
                level = len(match.group(1))
                title = match.group(2).strip()
                
                # 跳过主标题
                if level == 1:
                    continue
                
                # 目标层级(##)或者当前没有section时，创建新section
                if level <= self.target_section_level or current_section is None:
                    # 保存当前section
                    if current_section and current_content_lines:
                        current_section.content = '\n'.join(current_content_lines)
                        current_section.end_line = i - 1
                        sections.append(current_section)
                    
                    # 更新父级栈
                    while parent_stack and parent_stack[-1][0] >= level:
                        parent_stack.pop()
                    
                    parent_sections = [p[1] for p in parent_stack]
                    parent_stack.append((level, title))
                    
                    # 创建新section
                    current_section = MarkdownSection(
                        file_name=file_name,
                        title=main_title,
                        section_title=title,
                        section_level=level,
                        parent_sections=parent_sections.copy(),
                        start_line=i
                    )
                    current_content_lines = [line]
                else:
                    # 低层级标题作为内容的一部分
                    current_content_lines.append(line)
                    # 但仍然更新父级栈用于追踪
                    while parent_stack and parent_stack[-1][0] >= level:
                        parent_stack.pop()
                    parent_stack.append((level, title))
            else:
                current_content_lines.append(line)
        
        # 保存最后一个section
        if current_section and current_content_lines:
            current_section.content = '\n'.join(current_content_lines)
            current_section.end_line = len(lines) - 1
            sections.append(current_section)
        
        return sections
    
    def _is_valid_section(self, section: MarkdownSection) -> bool:
        """
        验证分片是否有效
        
        过滤条件:
        1. 内容长度足够
        2. 如果要求代码块，必须包含代码块
        3. 不是纯目录或引用
        """
        # 长度检查
        content_length = len(section.content.strip())
        if content_length < self.min_chunk_length:
            return False
        
        if content_length > self.max_chunk_length:
            # 超长分片需要进一步处理，暂时保留
            pass
        
        # 代码块检查
        if self.include_code_required and not section.code_blocks:
            return False
        
        # 内容质量检查 - 过滤纯链接/目录页
        text_without_links = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', section.content)
        text_without_code = re.sub(r'`[^`]+`', '', text_without_links)
        clean_text = re.sub(r'[#\-*\s]+', ' ', text_without_code).strip()
        
        if len(clean_text) < 50:
            return False
        
        return True
    
    def extract_code_blocks(self, content: str) -> List[CodeBlock]:
        """
        从内容中提取所有代码块
        
        Args:
            content: Markdown内容
            
        Returns:
            代码块列表
        """
        code_blocks = []
        for match in self.CODE_BLOCK_PATTERN.finditer(content):
            language = match.group(1) or "text"
            code = match.group(2).strip()
            code_blocks.append(CodeBlock(
                language=language,
                code=code,
                start_line=content[:match.start()].count('\n'),
                end_line=content[:match.end()].count('\n')
            ))
        return code_blocks
    
    def chunk_directory(
        self, 
        directory: Path,
        pattern: str = "*.md"
    ) -> Generator[MarkdownSection, None, None]:
        """
        分片目录下所有Markdown文件
        
        Args:
            directory: 目录路径
            pattern: 文件匹配模式
            
        Yields:
            分片对象
        """
        for file_path in sorted(directory.glob(pattern)):
            try:
                sections = self.parse_file(file_path)
                for section in sections:
                    yield section
            except Exception as e:
                print(f"Error processing {file_path}: {e}")
                continue


def get_code_language_display(lang: str) -> str:
    """
    获取代码语言的显示名称
    """
    lang_map = {
        'java': 'Java',
        'python': 'Python',
        'javascript': 'JavaScript',
        'js': 'JavaScript',
        'typescript': 'TypeScript',
        'ts': 'TypeScript',
        'csharp': 'C#',
        'cs': 'C#',
        'c#': 'C#',
        'cpp': 'C++',
        'c++': 'C++',
        'c': 'C',
        'php': 'PHP',
        'ruby': 'Ruby',
        'rb': 'Ruby',
        'go': 'Go',
        'golang': 'Go',
        'rust': 'Rust',
        'sql': 'SQL',
        'html': 'HTML',
        'xml': 'XML',
        'css': 'CSS',
        'shell': 'Shell',
        'bash': 'Bash',
        'sh': 'Shell',
        'yaml': 'YAML',
        'yml': 'YAML',
        'json': 'JSON',
        'text': 'General',
        '': 'General',
        'vbnet': 'VB.NET',
        'kotlin': 'Kotlin',
        'scala': 'Scala',
        'swift': 'Swift',
        'objective-c': 'Objective-C',
        'perl': 'Perl',
    }
    return lang_map.get(lang.lower(), lang.title() if lang else 'General')


if __name__ == "__main__":
    # 测试代码
    import sys
    
    if len(sys.argv) > 1:
        test_file = Path(sys.argv[1])
    else:
        test_file = Path("cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.md")
    
    if test_file.exists():
        chunker = MarkdownChunker(
            min_chunk_length=100,
            include_code_required=False
        )
        
        sections = chunker.parse_file(test_file)
        
        print(f"\n📄 文件: {test_file.name}")
        print(f"📊 共分片: {len(sections)} 个\n")
        
        for i, section in enumerate(sections):
            print(f"{'='*60}")
            print(f"分片 {i+1}: {section.section_title}")
            print(f"  层级: H{section.section_level}")
            print(f"  父级: {' > '.join(section.parent_sections) if section.parent_sections else '无'}")
            print(f"  代码块: {len(section.code_blocks)} 个")
            for cb in section.code_blocks:
                print(f"    - {cb.language}: {len(cb.code)} 字符")
            print(f"  内容长度: {len(section.content)} 字符")
            print(f"  内容预览: {section.content[:200]}...")
            print()
    else:
        print(f"文件不存在: {test_file}")
