"""
LLM 客户端封装

支持多种LLM服务商:
- OpenAI
- Azure OpenAI
- Anthropic Claude
- DeepSeek
- Ollama
- 自定义兼容OpenAI API的服务
"""
import os
import json
import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Any, AsyncGenerator
from dataclasses import dataclass
import httpx


@dataclass
class LLMResponse:
    """LLM响应结构"""
    content: str
    model: str
    usage: Dict[str, int]
    finish_reason: str
    raw_response: Optional[Dict] = None


class BaseLLMClient(ABC):
    """LLM客户端基类"""
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: str = "gpt-4o-mini",
        temperature: float = 0.1,
        max_tokens: int = 4096,
        timeout: float = 120.0
    ):
        self.api_key = api_key
        self.base_url = base_url
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.timeout = timeout
    
    @abstractmethod
    async def chat(
        self,
        messages: List[Dict[str, str]],
        **kwargs
    ) -> LLMResponse:
        """发送聊天请求"""
        pass
    
    @abstractmethod
    def chat_sync(
        self,
        messages: List[Dict[str, str]],
        **kwargs
    ) -> LLMResponse:
        """同步聊天请求"""
        pass


class OpenAICompatibleClient(BaseLLMClient):
    """OpenAI兼容API客户端
    
    支持所有兼容OpenAI API格式的服务商
    """
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: str = "gpt-4o-mini",
        temperature: float = 0.1,
        max_tokens: int = 4096,
        timeout: float = 120.0
    ):
        super().__init__(api_key, base_url, model, temperature, max_tokens, timeout)
        
        # 默认使用OpenAI
        if not self.base_url:
            self.base_url = "https://api.openai.com/v1"
        
        # 从环境变量获取API Key
        if not self.api_key:
            self.api_key = os.environ.get("OPENAI_API_KEY", "")
        # 仅在存在API Key时设置授权头，避免出现空的 'Bearer ' 值
        self.headers = {"Content-Type": "application/json"}
        if self.api_key:
            self.headers["Authorization"] = f"Bearer {self.api_key}"
    
    async def chat(
        self,
        messages: List[Dict[str, str]],
        **kwargs
    ) -> LLMResponse:
        """异步聊天请求"""
        url = f"{self.base_url.rstrip('/')}/chat/completions"
        
        payload = {
            "model": kwargs.get("model", self.model),
            "messages": messages,
            "temperature": kwargs.get("temperature", self.temperature),
            "max_tokens": kwargs.get("max_tokens", self.max_tokens),
        }
        
        # 添加JSON模式(如果支持)
        if kwargs.get("json_mode", False):
            payload["response_format"] = {"type": "json_object"}
        
        logger = logging.getLogger(__name__)
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                url,
                headers=self.headers,
                json=payload
            )
            response.raise_for_status()
            text = response.text
            try:
                data = response.json()
            except Exception as e:
                logger.warning(f"LLM returned non-JSON response or empty body: {e}")
                logger.debug(f"LLM raw response text: {text[:1000]}")
                return LLMResponse(
                    content=text or "",
                    model=self.model,
                    usage={},
                    finish_reason="unknown",
                    raw_response=None
                )

            # 尝试从多种响应结构中提取文本内容，兼容不同服务商
            content = ""
            finish_reason = "unknown"
            usage = data.get("usage", {}) if isinstance(data, dict) else {}

            try:
                # OpenAI-like
                content = data["choices"][0]["message"]["content"]
                finish_reason = data["choices"][0].get("finish_reason", "stop")
            except Exception:
                # Ollama-like
                try:
                    content = data.get("message", {}).get("content", "")
                    finish_reason = data.get("done_reason", "stop")
                except Exception:
                    # Anthropic-like or other shapes
                    if isinstance(data, dict):
                        # Look for common string fields
                        for key in ("text", "result", "content", "message"):
                            v = data.get(key)
                            if isinstance(v, str) and v.strip():
                                content = v
                                break
                        # As a last resort, serialize the whole object
                        if not content:
                            try:
                                content = json.dumps(data, ensure_ascii=False)
                            except Exception:
                                content = str(data)
                    else:
                        content = str(data)

        # Attach raw HTTP metadata for debugging
        raw_meta = None
        try:
            raw_meta = {
                'status_code': response.status_code,
                'url': url,
                'headers': dict(response.headers),
                'text': text
            }
        except Exception:
            raw_meta = {'text': text}

        return LLMResponse(
            content=content,
            model=data.get("model", self.model) if isinstance(data, dict) else self.model,
            usage=usage,
            finish_reason=finish_reason,
            raw_response=data if isinstance(data, dict) else raw_meta
        )
    
    def chat_sync(
        self,
        messages: List[Dict[str, str]],
        **kwargs
    ) -> LLMResponse:
        """同步聊天请求"""
        url = f"{self.base_url.rstrip('/')}/chat/completions"
        
        payload = {
            "model": kwargs.get("model", self.model),
            "messages": messages,
            "temperature": kwargs.get("temperature", self.temperature),
            "max_tokens": kwargs.get("max_tokens", self.max_tokens),
        }
        
        if kwargs.get("json_mode", False):
            payload["response_format"] = {"type": "json_object"}
        
        logger = logging.getLogger(__name__)
        with httpx.Client(timeout=self.timeout) as client:
            response = client.post(
                url,
                headers=self.headers,
                json=payload
            )
            response.raise_for_status()
            text = response.text
            try:
                data = response.json()
            except Exception as e:
                logger.warning(f"LLM returned non-JSON response or empty body: {e}")
                logger.debug(f"LLM raw response text: {text[:1000]}")
                return LLMResponse(
                    content=text or "",
                    model=self.model,
                    usage={},
                    finish_reason="unknown",
                    raw_response=None
                )

            # Defensive content extraction (sync path)
            content = ""
            finish_reason = "unknown"
            usage = data.get("usage", {}) if isinstance(data, dict) else {}

            try:
                content = data["choices"][0]["message"]["content"]
                finish_reason = data["choices"][0].get("finish_reason", "stop")
            except Exception:
                try:
                    content = data.get("message", {}).get("content", "")
                    finish_reason = data.get("done_reason", "stop")
                except Exception:
                    if isinstance(data, dict):
                        for key in ("text", "result", "content", "message"):
                            v = data.get(key)
                            if isinstance(v, str) and v.strip():
                                content = v
                                break
                        if not content:
                            try:
                                content = json.dumps(data, ensure_ascii=False)
                            except Exception:
                                content = str(data)
                    else:
                        content = str(data)

        # Attach raw HTTP metadata for debugging (sync path)
        raw_meta = None
        try:
            raw_meta = {
                'status_code': response.status_code,
                'url': url,
                'headers': dict(response.headers),
                'text': text
            }
        except Exception:
            raw_meta = {'text': text}

        return LLMResponse(
            content=content,
            model=data.get("model", self.model) if isinstance(data, dict) else self.model,
            usage=usage,
            finish_reason=finish_reason,
            raw_response=data if isinstance(data, dict) else raw_meta
        )


class AnthropicClient(BaseLLMClient):
    """Anthropic Claude客户端"""
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: str = "claude-3-5-sonnet-20241022",
        temperature: float = 0.1,
        max_tokens: int = 4096,
        timeout: float = 120.0
    ):
        super().__init__(api_key, base_url, model, temperature, max_tokens, timeout)
        
        if not self.base_url:
            self.base_url = "https://api.anthropic.com"
        
        if not self.api_key:
            self.api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        # 仅在存在API Key时设置x-api-key，避免空值导致的请求错误
        self.headers = {"Content-Type": "application/json", "anthropic-version": "2023-06-01"}
        if self.api_key:
            self.headers["x-api-key"] = self.api_key
    
    async def chat(
        self,
        messages: List[Dict[str, str]],
        **kwargs
    ) -> LLMResponse:
        """异步聊天请求"""
        url = f"{self.base_url.rstrip('/')}/v1/messages"
        
        # Anthropic格式转换
        system_message = ""
        chat_messages = []
        
        for msg in messages:
            if msg["role"] == "system":
                system_message = msg["content"]
            else:
                chat_messages.append({
                    "role": msg["role"],
                    "content": msg["content"]
                })
        
        payload = {
            "model": kwargs.get("model", self.model),
            "messages": chat_messages,
            "max_tokens": kwargs.get("max_tokens", self.max_tokens),
            "temperature": kwargs.get("temperature", self.temperature),
        }
        
        if system_message:
            payload["system"] = system_message
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                url,
                headers=self.headers,
                json=payload
            )
            response.raise_for_status()
            data = response.json()
        
        content = ""
        if data.get("content"):
            content = data["content"][0].get("text", "")
        
        return LLMResponse(
            content=content,
            model=data.get("model", self.model),
            usage={
                "prompt_tokens": data.get("usage", {}).get("input_tokens", 0),
                "completion_tokens": data.get("usage", {}).get("output_tokens", 0),
                "total_tokens": data.get("usage", {}).get("input_tokens", 0) + data.get("usage", {}).get("output_tokens", 0)
            },
            finish_reason=data.get("stop_reason", "end_turn"),
            raw_response=data
        )
    
    def chat_sync(
        self,
        messages: List[Dict[str, str]],
        **kwargs
    ) -> LLMResponse:
        """同步聊天请求"""
        url = f"{self.base_url.rstrip('/')}/v1/messages"
        
        system_message = ""
        chat_messages = []
        
        for msg in messages:
            if msg["role"] == "system":
                system_message = msg["content"]
            else:
                chat_messages.append({
                    "role": msg["role"],
                    "content": msg["content"]
                })
        
        payload = {
            "model": kwargs.get("model", self.model),
            "messages": chat_messages,
            "max_tokens": kwargs.get("max_tokens", self.max_tokens),
            "temperature": kwargs.get("temperature", self.temperature),
        }
        
        if system_message:
            payload["system"] = system_message
        
        with httpx.Client(timeout=self.timeout) as client:
            response = client.post(
                url,
                headers=self.headers,
                json=payload
            )
            response.raise_for_status()
            data = response.json()
        
        content = ""
        if data.get("content"):
            content = data["content"][0].get("text", "")
        
        return LLMResponse(
            content=content,
            model=data.get("model", self.model),
            usage={
                "prompt_tokens": data.get("usage", {}).get("input_tokens", 0),
                "completion_tokens": data.get("usage", {}).get("output_tokens", 0),
                "total_tokens": data.get("usage", {}).get("input_tokens", 0) + data.get("usage", {}).get("output_tokens", 0)
            },
            finish_reason=data.get("stop_reason", "end_turn"),
            raw_response=data
        )


class OllamaClient(BaseLLMClient):
    """Ollama本地模型客户端"""
    
    def __init__(
        self,
        api_key: Optional[str] = None,  # Ollama不需要API Key
        base_url: Optional[str] = None,
        model: str = "llama3.2",
        temperature: float = 0.1,
        max_tokens: int = 4096,
        timeout: float = 300.0  # 本地模型可能需要更长时间
    ):
        super().__init__(api_key, base_url, model, temperature, max_tokens, timeout)
        
        if not self.base_url:
            self.base_url = "http://localhost:11434"
    
    async def chat(
        self,
        messages: List[Dict[str, str]],
        **kwargs
    ) -> LLMResponse:
        """异步聊天请求"""
        url = f"{self.base_url.rstrip('/')}/api/chat"
        
        payload = {
            "model": kwargs.get("model", self.model),
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": kwargs.get("temperature", self.temperature),
                "num_predict": kwargs.get("max_tokens", self.max_tokens),
            }
        }
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(url, json=payload)
            response.raise_for_status()
            data = response.json()
        
        return LLMResponse(
            content=data.get("message", {}).get("content", ""),
            model=data.get("model", self.model),
            usage={
                "prompt_tokens": data.get("prompt_eval_count", 0),
                "completion_tokens": data.get("eval_count", 0),
                "total_tokens": data.get("prompt_eval_count", 0) + data.get("eval_count", 0)
            },
            finish_reason=data.get("done_reason", "stop"),
            raw_response=data
        )
    
    def chat_sync(
        self,
        messages: List[Dict[str, str]],
        **kwargs
    ) -> LLMResponse:
        """同步聊天请求"""
        url = f"{self.base_url.rstrip('/')}/api/chat"
        
        payload = {
            "model": kwargs.get("model", self.model),
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": kwargs.get("temperature", self.temperature),
                "num_predict": kwargs.get("max_tokens", self.max_tokens),
            }
        }
        
        with httpx.Client(timeout=self.timeout) as client:
            response = client.post(url, json=payload)
            response.raise_for_status()
            data = response.json()
        
        return LLMResponse(
            content=data.get("message", {}).get("content", ""),
            model=data.get("model", self.model),
            usage={
                "prompt_tokens": data.get("prompt_eval_count", 0),
                "completion_tokens": data.get("eval_count", 0),
                "total_tokens": data.get("prompt_eval_count", 0) + data.get("eval_count", 0)
            },
            finish_reason=data.get("done_reason", "stop"),
            raw_response=data
        )


def create_llm_client(
    provider: str = "openai",
    api_key: Optional[str] = None,
    base_url: Optional[str] = None,
    model: Optional[str] = None,
    **kwargs
) -> BaseLLMClient:
    """
    创建LLM客户端工厂方法
    
    Args:
        provider: 服务商名称 (openai, azure, anthropic, deepseek, ollama, custom)
        api_key: API密钥
        base_url: 自定义API地址
        model: 模型名称
        **kwargs: 其他参数
        
    Returns:
        LLM客户端实例
    """
    provider = provider.lower()
    
    # 默认模型映射
    default_models = {
        "openai": "gpt-4o-mini",
        "azure": "gpt-4o-mini",
        "anthropic": "claude-3-5-sonnet-20241022",
        "deepseek": "deepseek-chat",
        "ollama": "llama3.2",
        "custom": "gpt-4o-mini",
    }
    
    # 默认API地址映射
    default_urls = {
        "openai": "https://api.openai.com/v1",
        "anthropic": "https://api.anthropic.com",
        "deepseek": "https://api.deepseek.com/v1",
        "ollama": "http://localhost:11434",
    }
    
    # 环境变量映射
    env_keys = {
        "openai": "OPENAI_API_KEY",
        "azure": "AZURE_OPENAI_API_KEY",
        "anthropic": "ANTHROPIC_API_KEY",
        "deepseek": "DEEPSEEK_API_KEY",
    }
    
    # 获取API Key
    if not api_key and provider in env_keys:
        api_key = os.environ.get(env_keys[provider], "")
    
    # 获取模型名称
    if not model:
        model = default_models.get(provider, "gpt-4o-mini")
    
    # 获取API地址
    if not base_url:
        base_url = default_urls.get(provider)
    
    # 创建客户端
    if provider == "anthropic":
        return AnthropicClient(
            api_key=api_key,
            base_url=base_url,
            model=model,
            **kwargs
        )
    elif provider == "ollama":
        return OllamaClient(
            base_url=base_url,
            model=model,
            **kwargs
        )
    else:
        # OpenAI兼容的服务商 (openai, azure, deepseek, custom)
        return OpenAICompatibleClient(
            api_key=api_key,
            base_url=base_url,
            model=model,
            **kwargs
        )


# 测试代码
if __name__ == "__main__":
    async def test_client():
        # 测试OpenAI
        client = create_llm_client(
            provider="openai",
            model="gpt-4o-mini"
        )
        
        messages = [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "Say hello in Chinese."}
        ]
        
        try:
            response = await client.chat(messages)
            print(f"Model: {response.model}")
            print(f"Response: {response.content}")
            print(f"Usage: {response.usage}")
        except Exception as e:
            print(f"Error: {e}")
    
    asyncio.run(test_client())
