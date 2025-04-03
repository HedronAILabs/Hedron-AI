import asyncio
import time
from typing import Dict, List, Optional, Callable, Awaitable
from dataclasses import dataclass
from pydantic import BaseModel, Field
from prometheus_client import Gauge, Counter, Histogram
from redis.asyncio import RedisCluster
from circuitbreaker import circuit
import psutil
import aiohttp

# ======================
# Core Data Models
# ======================

class HealthCheckConfig(BaseModel):
    check_interval: float = Field(5.0, gt=0.0, description="Seconds between checks")
    timeout: float = Field(3.0, gt=0.0)
    failure_threshold: int = Field(3, gt=0)
    success_threshold: int = Field(2, gt=0)
    check_types: List[str] = Field(["heartbeat", "resources"], min_items=1)

class AgentHealthStatus(BaseModel):
    last_seen: float
    consecutive_failures: int = 0
    consecutive_successes: int = 0
    reported_status: str = "UNKNOWN"

# ======================
# Metrics Setup
# ======================

HEALTH_CHECK_DURATION = Histogram(
    'health_check_duration_seconds',
    'Latency of health checks',
    ['check_type'],
    buckets=[0.1, 0.5, 1.0, 2.0, 5.0]
)

HEALTH_CHECK_FAILURES = Counter(
    'health_check_failures_total',
    'Total failed health checks',
    ['check_type', 'failure_reason']
)

AGENT_STATUS_GAUGE = Gauge(
    'agent_health_status',
    'Current health status of agents',
    ['agent_id', 'status']
)

# ======================
# Health Check Implementations
# ======================

class HealthCheckBase:
    def __init__(self, agent_id: str, redis: RedisCluster):
        self.agent_id = agent_id
        self.redis = redis

    async def execute(self) -> bool:
        raise NotImplementedError

class HeartbeatCheck(HealthCheckBase):
    async def execute(self) -> bool:
        key = f"agent:{self.agent_id}:heartbeat"
        try:
            last_heartbeat = await self.redis.get(key)
            return float(last_heartbeat) > time.time() - 30
        except Exception as e:
            HEALTH_CHECK_FAILURES.labels("heartbeat", "redis_error").inc()
            return False

class ResourceCheck(HealthCheckBase):
    async def execute(self) -> bool:
        try:
            stats = await self.redis.hgetall(f"agent:{self.agent_id}:stats")
            cpu = float(stats.get('cpu', 0))
            mem = float(stats.get('mem', 0))
            return cpu < 90.0 and mem < 85.0
        except Exception as e:
            HEALTH_CHECK_FAILURES.labels("resources", "stats_error").inc()
            return False

class GRPCCheck(HealthCheckBase):
    def __init__(self, agent_id: str, redis: RedisCluster, endpoint: str = "grpc.health.v1.Health"):
        super().__init__(agent_id, redis)
        self.endpoint = endpoint

    async def execute(self) -> bool:
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(
                    f"http://{self.agent_id}:50051/{self.endpoint}",
                    timeout=2
                ) as response:
                    return response.status == 200
            except Exception as e:
                HEALTH_CHECK_FAILURES.labels("grpc", "network_error").inc()
                return False

# ======================
# Health Monitor Core
# ======================

class HealthMonitor:
    def __init__(
        self,
        redis: RedisCluster,
        state_machine_callback: Callable[[str, str], Awaitable[None]],
        config: HealthCheckConfig = HealthCheckConfig()
    ):
        self.redis = redis
        self.config = config
        self.agents: Dict[str, AgentHealthStatus] = {}
        self._active_checks: Dict[str, asyncio.Task] = {}
        self._state_machine_cb = state_machine_callback
        self._lock = asyncio.Lock()
        self._session = aiohttp.ClientSession()
        self._check_registry = {
            "heartbeat": HeartbeatCheck,
            "resources": ResourceCheck,
            "grpc": GRPCCheck
        }

    async def start_monitoring(self, agent_ids: List[str]):
        """Start health monitoring for multiple agents"""
        async with self._lock:
            for agent_id in agent_ids:
                if agent_id not in self._active_checks:
                    self._active_checks[agent_id] = asyncio.create_task(
                        self._agent_loop(agent_id)
                    )

    async def stop_monitoring(self, agent_id: str):
        """Stop health monitoring for an agent"""
        async with self._lock:
            if task := self._active_checks.pop(agent_id, None):
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

    @circuit(failure_threshold=3, recovery_timeout=60)
    async def _agent_loop(self, agent_id: str):
        """Continuous health check loop per agent"""
        while True:
            try:
                async with self.redis.lock(f"healthcheck:{agent_id}", timeout=10):
                    status = await self._check_agent(agent_id)
                    await self._update_health_status(agent_id, status)
                    await self._trigger_state_change(agent_id, status)
                
                await asyncio.sleep(self.config.check_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                HEALTH_CHECK_FAILURES.labels("system", "monitor_error").inc()
                await asyncio.sleep(5)

    async def _check_agent(self, agent_id: str) -> bool:
        """Execute all configured health checks"""
        results = []
        for check_type in self.config.check_types:
            checker = self._check_registry[check_type](agent_id, self.redis)
            with HEALTH_CHECK_DURANCE.labels(check_type).time():
                result = await checker.execute()
                results.append(result)
        
        return all(results)

    async def _update_health_status(self, agent_id: str, success: bool):
        """Update health status with failure tracking"""
        async with self.redis.pipeline(transaction=True) as pipe:
            current = await pipe.hgetall(f"agent:{agent_id}:health")
            current_status = AgentHealthStatus(**current) if current else AgentHealthStatus(last_seen=time.time())

            new_status = current_status.copy(update={
                "last_seen": time.time(),
                "consecutive_failures": 0 if success else current_status.consecutive_failures + 1,
                "consecutive_successes": current_status.consecutive_successes + 1 if success else 0
            })

            pipe.hset(f"agent:{agent_id}:health", mapping=new_status.dict())
            await pipe.execute()

        AGENT_STATUS_GAUGE.labels(agent_id, "HEALTHY" if success else "UNHEALTHY").set(int(success))

    async def _trigger_state_change(self, agent_id: str, healthy: bool):
        """Handle state transitions based on health status"""
        current_status = await self.redis.hgetall(f"agent:{agent_id}:health")
        status = AgentHealthStatus(**current_status)

        if status.consecutive_failures >= self.config.failure_threshold:
            await self._state_machine_cb(agent_id, "DEGRADED")
            await self._isolate_agent(agent_id)
        elif status.consecutive_successes >= self.config.success_threshold:
            await self._state_machine_cb(agent_id, "ACTIVE")

    async def _isolate_agent(self, agent_id: str):
        """Isolate unhealthy agent from the cluster"""
        async with self.redis.pipeline() as pipe:
            pipe.srem("cluster:active_nodes", agent_id)
            pipe.sadd("cluster:isolated_nodes", agent_id)
            await pipe.execute()

    async def cluster_wide_health(self) -> Dict[str, dict]:
        """Get health status for entire cluster"""
        keys = await self.redis.keys("agent:*:health")
        pipeline = self.redis.pipeline()
        
        for key in keys:
            pipeline.hgetall(key)
        
        results = await pipeline.execute()
        return {
            key.decode().split(':')[1]: AgentHealthStatus(**{k.decode(): v.decode() for k,v in res.items()})
            for key, res in zip(keys, results)
        }

    async def force_check(self, agent_id: str) -> bool:
        """Immediate health check bypassing normal interval"""
        async with self.redis.lock(f"healthcheck:{agent_id}:force", timeout=5):
            status = await self._check_agent(agent_id)
            await self._update_health_status(agent_id, status)
            return status

# ======================
# Utility Functions
# ======================

async def system_health_check() -> dict:
    """Check local system resources"""
    return {
        "cpu": psutil.cpu_percent(),
        "memory": psutil.virtual_memory().percent,
        "disk": psutil.disk_usage('/').percent
    }

async def cleanup():
    """Cleanup resources"""
    await self._session.close()

# ======================
# Initialization Example
# ======================

async def main():
    redis = await RedisCluster.from_url("redis://cluster-node:6379")
    
    async def state_change_callback(agent_id: str, new_state: str):
        await redis.publish(f"agent:{agent_id}:state", new_state)

    config = HealthCheckConfig(
        check_interval=10.0,
        timeout=5.0,
        check_types=["heartbeat", "grpc"]
    )
    
    monitor = HealthMonitor(redis, state_change_callback, config)
    await monitor.start_monitoring(["agent-1", "agent-2"])
    
    try:
        while True:
            await asyncio.sleep(3600)  # Run indefinitely
    finally:
        await cleanup()

if __name__ == "__main__":
    asyncio.run(main())
