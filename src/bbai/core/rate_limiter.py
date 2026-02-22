"""Rate limiting using Token Bucket algorithm.

Uses aiolimiter for asyncio-compatible rate limiting.
Implements both global rate limiting and per-tool rate limiting.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

from aiolimiter import AsyncLimiter

from bbai.core.config_models import RateLimitConfig


@dataclass
class RateLimitStats:
    """Statistics for rate limiter."""

    total_requests: int = 0
    throttled_requests: int = 0
    total_wait_time: float = 0.0


class RateLimiter:
    """Token bucket rate limiter for tool execution.
    
    Uses the aiolimiter library which implements the leaky bucket algorithm.
    This provides smooth rate limiting with burst capability.
    
    Usage:
        limiter = RateLimiter(RateLimitConfig())
        
        async with limiter:
            await run_tool()
            
    Or as decorator:
        @limiter.limit
        async def my_tool():
            pass
    """

    def __init__(self, config: RateLimitConfig | None = None):
        self.config = config or RateLimitConfig()
        
        # Main rate limiter for requests per second
        self._limiter = AsyncLimiter(
            max_rate=self.config.requests_per_second,
            time_period=1.0,  # Per second
        )
        
        # Semaphore for concurrent tool execution
        self._concurrent_sem = asyncio.Semaphore(self.config.concurrent_tools)
        
        # Statistics
        self._stats = RateLimitStats()
        self._lock = asyncio.Lock()

    async def __aenter__(self) -> RateLimiter:
        """Acquire the rate limiter."""
        import time
        
        start_time = time.time()
        
        # Acquire concurrent execution slot first
        await self._concurrent_sem.acquire()
        
        # Then acquire rate limit
        await self._limiter.__aenter__()
        
        elapsed = time.time() - start_time
        
        async with self._lock:
            self._stats.total_requests += 1
            if elapsed > 0.01:  # Considered throttled if waited more than 10ms
                self._stats.throttled_requests += 1
            self._stats.total_wait_time += elapsed
        
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Release the rate limiter."""
        await self._limiter.__aexit__(exc_type, exc_val, exc_tb)
        self._concurrent_sem.release()

    def limit(self, func: Any) -> Any:
        """Decorator to rate limit a function.
        
        Usage:
            @limiter.limit
            async def my_tool():
                pass
        """
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            async with self:
                return await func(*args, **kwargs)
        return wrapper

    def get_stats(self) -> RateLimitStats:
        """Get current rate limiting statistics."""
        return RateLimitStats(
            total_requests=self._stats.total_requests,
            throttled_requests=self._stats.throttled_requests,
            total_wait_time=self._stats.total_wait_time,
        )

    def reset_stats(self) -> None:
        """Reset statistics."""
        self._stats = RateLimitStats()


class MultiRateLimiter:
    """Multiple rate limiters for different contexts.
    
    Provides separate rate limits for:
    - Global requests
    - Per-domain requests
    - Per-tool requests
    """

    def __init__(self, config: RateLimitConfig | None = None):
        self.config = config or RateLimitConfig()
        
        # Global limiter
        self.global_limiter = RateLimiter(self.config)
        
        # Per-domain limiters
        self._domain_limiters: dict[str, RateLimiter] = {}
        
        # Per-tool limiters
        self._tool_limiters: dict[str, RateLimiter] = {}

    def get_domain_limiter(self, domain: str) -> RateLimiter:
        """Get or create rate limiter for a domain."""
        if domain not in self._domain_limiters:
            # Domain limiters are more restrictive
            domain_config = RateLimitConfig(
                requests_per_second=self.config.requests_per_second / 2,
                burst_size=max(1, self.config.burst_size // 2),
                concurrent_tools=max(1, self.config.concurrent_tools // 2),
            )
            self._domain_limiters[domain] = RateLimiter(domain_config)
        return self._domain_limiters[domain]

    def get_tool_limiter(self, tool_name: str) -> RateLimiter:
        """Get or create rate limiter for a tool."""
        if tool_name not in self._tool_limiters:
            self._tool_limiters[tool_name] = RateLimiter(self.config)
        return self._tool_limiters[tool_name]

    def acquire(
        self,
        domain: str | None = None,
        tool_name: str | None = None,
    ) -> "MultiRateLimitContext":
        """Acquire permissions from all relevant limiters.
        
        Args:
            domain: Domain being accessed (optional)
            tool_name: Tool being used (optional)
            
        Returns:
            MultiRateLimitContext for async context manager
        """
        return MultiRateLimitContext(self, domain, tool_name)

    def get_all_stats(self) -> dict[str, RateLimitStats]:
        """Get statistics from all limiters."""
        stats = {"global": self.global_limiter.get_stats()}
        
        for domain, limiter in self._domain_limiters.items():
            stats[f"domain:{domain}"] = limiter.get_stats()
            
        for tool, limiter in self._tool_limiters.items():
            stats[f"tool:{tool}"] = limiter.get_stats()
            
        return stats


class MultiRateLimitContext:
    """Async context manager for multiple rate limiters."""

    def __init__(
        self,
        multi_limiter: MultiRateLimiter,
        domain: str | None,
        tool_name: str | None,
    ):
        self.multi_limiter = multi_limiter
        self.domain = domain
        self.tool_name = tool_name
        self._contexts: list[RateLimiter] = []

    async def __aenter__(self) -> MultiRateLimitContext:
        # Acquire global first
        await self.multi_limiter.global_limiter.__aenter__()
        self._contexts.append(self.multi_limiter.global_limiter)

        # Acquire domain limiter if specified
        if self.domain:
            domain_limiter = self.multi_limiter.get_domain_limiter(self.domain)
            await domain_limiter.__aenter__()
            self._contexts.append(domain_limiter)

        # Acquire tool limiter if specified
        if self.tool_name:
            tool_limiter = self.multi_limiter.get_tool_limiter(self.tool_name)
            await tool_limiter.__aenter__()
            self._contexts.append(tool_limiter)

        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        # Release in reverse order
        for limiter in reversed(self._contexts):
            await limiter.__aexit__(exc_type, exc_val, exc_tb)
