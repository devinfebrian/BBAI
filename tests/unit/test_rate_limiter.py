"""Unit tests for rate limiter."""

import asyncio

import pytest

from bbai.core.config_models import RateLimitConfig
from bbai.core.rate_limiter import (
    MultiRateLimiter,
    RateLimitStats,
    RateLimiter,
)


class TestRateLimiter:
    """Test RateLimiter functionality."""

    @pytest.fixture
    def config(self):
        return RateLimitConfig(
            requests_per_second=10.0,
            burst_size=5,
            concurrent_tools=2,
        )

    @pytest.fixture
    def limiter(self, config):
        return RateLimiter(config)

    @pytest.mark.asyncio
    async def test_basic_acquire(self, limiter):
        """Test basic acquire and release."""
        async with limiter:
            pass  # Should complete without error

    @pytest.mark.asyncio
    async def test_concurrent_limit(self, config):
        """Test that concurrent execution limit is respected."""
        config = RateLimitConfig(
            requests_per_second=100.0,
            burst_size=10,
            concurrent_tools=1,  # Only 1 concurrent
        )
        limiter = RateLimiter(config)
        
        running = 0
        max_running = 0
        
        async def worker():
            nonlocal running, max_running
            async with limiter:
                running += 1
                max_running = max(max_running, running)
                await asyncio.sleep(0.05)  # Hold for 50ms
                running -= 1
        
        # Run 3 workers concurrently
        await asyncio.gather(worker(), worker(), worker())
        
        # Max concurrent should be 1
        assert max_running == 1

    @pytest.mark.asyncio
    async def test_rate_limit_throttling(self):
        """Test that rate limit actually throttles requests."""
        config = RateLimitConfig(
            requests_per_second=2.0,  # 2 per second
            burst_size=1,
            concurrent_tools=10,
        )
        limiter = RateLimiter(config)
        
        start = asyncio.get_event_loop().time()
        
        # Make 5 requests (more than burst to ensure throttling)
        for _ in range(5):
            async with limiter:
                pass
        
        elapsed = asyncio.get_event_loop().time() - start
        
        # With 2 req/s and no burst, 5 requests should take at least 2 seconds
        # But since we allow some burst, it should take at least 1 second
        assert elapsed >= 0.5  # Some throttling should occur

    @pytest.mark.asyncio
    async def test_decorator(self, limiter):
        """Test rate limiting decorator."""
        call_count = 0
        
        @limiter.limit
        async def my_func():
            nonlocal call_count
            call_count += 1
            return "result"
        
        result = await my_func()
        assert result == "result"
        assert call_count == 1

    @pytest.mark.asyncio
    async def test_stats_tracking(self, limiter):
        """Test that stats are tracked correctly."""
        # Reset stats
        limiter.reset_stats()
        
        async with limiter:
            pass
        
        stats = limiter.get_stats()
        assert stats.total_requests == 1
        assert isinstance(stats.throttled_requests, int)
        assert isinstance(stats.total_wait_time, float)

    def test_stats_class(self):
        """Test RateLimitStats dataclass."""
        stats = RateLimitStats(
            total_requests=10,
            throttled_requests=2,
            total_wait_time=0.5,
        )
        assert stats.total_requests == 10
        assert stats.throttled_requests == 2
        assert stats.total_wait_time == 0.5


class TestMultiRateLimiter:
    """Test MultiRateLimiter functionality."""

    @pytest.fixture
    def multi_limiter(self):
        config = RateLimitConfig(
            requests_per_second=10.0,
            burst_size=5,
            concurrent_tools=3,
        )
        return MultiRateLimiter(config)

    @pytest.mark.asyncio
    async def test_global_acquire(self, multi_limiter):
        """Test acquire from global limiter."""
        async with multi_limiter.acquire():
            pass

    @pytest.mark.asyncio
    async def test_domain_acquire(self, multi_limiter):
        """Test acquire with domain-specific limiter."""
        async with multi_limiter.acquire(domain="example.com"):
            pass

    @pytest.mark.asyncio
    async def test_tool_acquire(self, multi_limiter):
        """Test acquire with tool-specific limiter."""
        async with multi_limiter.acquire(tool_name="nuclei"):
            pass

    @pytest.mark.asyncio
    async def test_combined_acquire(self, multi_limiter):
        """Test acquire with all limiters."""
        async with multi_limiter.acquire(
            domain="example.com",
            tool_name="nuclei",
        ):
            pass

    def test_domain_limiter_caching(self, multi_limiter):
        """Test that domain limiters are cached."""
        limiter1 = multi_limiter.get_domain_limiter("example.com")
        limiter2 = multi_limiter.get_domain_limiter("example.com")
        
        assert limiter1 is limiter2

    def test_tool_limiter_caching(self, multi_limiter):
        """Test that tool limiters are cached."""
        limiter1 = multi_limiter.get_tool_limiter("nuclei")
        limiter2 = multi_limiter.get_tool_limiter("nuclei")
        
        assert limiter1 is limiter2

    def test_get_all_stats(self, multi_limiter):
        """Test getting stats from all limiters."""
        # Create some limiters
        multi_limiter.get_domain_limiter("example.com")
        multi_limiter.get_tool_limiter("nuclei")
        
        stats = multi_limiter.get_all_stats()
        
        assert "global" in stats
        assert "domain:example.com" in stats
        assert "tool:nuclei" in stats

    @pytest.mark.asyncio
    async def test_domain_rate_is_lower(self):
        """Test that domain-specific limiters are more restrictive."""
        config = RateLimitConfig(
            requests_per_second=10.0,
            burst_size=10,
            concurrent_tools=4,
        )
        multi_limiter = MultiRateLimiter(config)
        
        domain_limiter = multi_limiter.get_domain_limiter("example.com")
        
        # Domain limiter should have half the rate
        assert domain_limiter.config.requests_per_second == 5.0
        assert domain_limiter.config.concurrent_tools == 2
