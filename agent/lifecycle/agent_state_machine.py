import asyncio
from enum import Enum, auto
from dataclasses import dataclass
from typing import Dict, Type, Callable, Optional, Awaitable
from pydantic import BaseModel, validator
from prometheus_client import Gauge, Counter, Histogram
from redis.asyncio import RedisCluster
from circuitbreaker import circuit

# ======================
# State Machine Core
# ======================

class AgentState(Enum):
    BOOTSTRAP = auto()
    SYNCING = auto()
    ACTIVE = auto()
    PAUSED = auto()
    RECOVERING = auto()
    TERMINATING = auto()
    DEGRADED = auto()

class StateTransitionEvent(BaseModel):
    event_type: str
    payload: dict
    correlation_id: str
    timestamp: float

    @validator('event_type')
    def validate_event_type(cls, v):
        if not v.startswith('agent.'):
            raise ValueError("Invalid event type namespace")
        return v

@dataclass(frozen=True)
class StateTransition:
    source: AgentState
    target: AgentState
    guard: Optional[Callable[[StateTransitionEvent], Awaitable[bool]]] = None
    before_transition: Optional[Callable[[], Awaitable[None]]] = None
    after_transition: Optional[Callable[[], Awaitable[None]]] = None

class DistributedLock:
    def __init__(self, redis: RedisCluster, lock_key: str, ttl: int = 30):
        self.redis = redis
        self.lock_key = f"statelock:{lock_key}"
        self.ttl = ttl

    async def __aenter__(self):
        while True:
            acquired = await self.redis.set(self.lock_key, "locked", nx=True, ex=self.ttl)
            if acquired:
                return
            await asyncio.sleep(0.1)

    async def __aexit__(self, *args):
        await self.redis.delete(self.lock_key)

class AgentStateMachine:
    _transitions: Dict[AgentState, Dict[str, StateTransition]] = {}
    _state_handlers: Dict[AgentState, Type[StateHandler]] = {}
    _plugins = []
    
    # Prometheus Metrics
    STATE_GAUGE = Gauge('agent_current_state', 'Current agent state', ['agent_id'])
    TRANSITION_COUNTER = Counter('agent_state_transitions', 'State transition count', ['from', 'to'])
    TRANSITION_TIME = Histogram('agent_transition_duration', 'State transition latency', ['transition'])

    def __init__(self, agent_id: str, redis: RedisCluster, initial_state: AgentState = AgentState.BOOTSTRAP):
        self.agent_id = agent_id
        self._current_state = initial_state
        self.redis = redis
        self._state_cache = {}
        self._event_queue = asyncio.Queue(maxsize=1000)
        self._persistence_lock = asyncio.Lock()
        
        # Initialize state handlers
        for state in AgentState:
            handler_cls = self._state_handlers.get(state, DefaultStateHandler)
            self._state_cache[state] = handler_cls(self)

    @classmethod
    def register_transition(cls, transition: StateTransition):
        cls._transitions.setdefault(transition.source, {})[transition.target] = transition
        return transition

    @classmethod
    def register_state_handler(cls, state: AgentState):
        def decorator(handler_cls: Type[StateHandler]):
            cls._state_handlers[state] = handler_cls
            return handler_cls
        return decorator

    @classmethod
    def register_plugin(cls, plugin):
        cls._plugins.append(plugin)

    @circuit(failure_threshold=5, recovery_timeout=30)
    async def transition(self, target_state: AgentState, event: StateTransitionEvent):
        async with DistributedLock(self.redis, self.agent_id):
            current_handler = self._state_cache[self._current_state]
            transition = self._transitions.get(self._current_state, {}).get(target_state)

            if not transition:
                raise IllegalStateTransitionError(
                    f"No transition from {self._current_state} to {target_state}"
                )

            # Execute guard condition
            if transition.guard and not await transition.guard(event):
                raise GuardConditionFailedError("Transition guard check failed")

            # Pre-transition hooks
            await self._execute_hooks('before_transition', transition, event)

            # State exit
            await current_handler.on_exit()

            # Update metrics
            self.TRANSITION_COUNTER.labels(self._current_state.name, target_state.name).inc()

            # Perform state transition
            with self.TRANSITION_TIME.labels(f"{self._current_state.name}->{target_state.name}").time():
                self._current_state = target_state
                self.STATE_GAUGE.labels(self.agent_id).set(target_state.value)
                
                # Persist state atomically
                async with self._persistence_lock:
                    await self._persist_state(target_state, event)

            # State entry
            new_handler = self._state_cache[target_state]
            await new_handler.on_enter(event)

            # Post-transition hooks
            await self._execute_hooks('after_transition', transition, event)

            return target_state

    async def _persist_state(self, state: AgentState, event: StateTransitionEvent):
        """Atomically persist state with event log"""
        pipe = self.redis.pipeline(transaction=True)
        pipe.hset(f"agent:{self.agent_id}", "state", state.name)
        pipe.xadd(f"agent:{self.agent_id}:events", event.dict())
        await pipe.execute()

    async def _execute_hooks(self, hook_type: str, transition: StateTransition, event: StateTransitionEvent):
        """Execute registered hooks and plugins"""
        hook_method = getattr(transition, hook_type, None)
        if hook_method:
            await hook_method()
            
        for plugin in self._plugins:
            plugin_hook = getattr(plugin, hook_type, None)
            if plugin_hook:
                await plugin_hook(self, transition, event)

    async def event_loop(self):
        """Main event processing loop"""
        while True:
            event = await self._event_queue.get()
            try:
                await self._process_event(event)
            except Exception as e:
                await self._handle_event_error(e, event)

    async def _process_event(self, event: StateTransitionEvent):
        """Process single event with retry logic"""
        max_retries = 3
        for attempt in range(max_retries):
            try:
                handler = self._state_cache[self._current_state]
                await handler.handle_event(event)
                return
            except RecoverableError as e:
                if attempt == max_retries - 1:
                    await self.transition(AgentState.DEGRADED, event)
                await asyncio.sleep(2 ** attempt)
            except FatalError as e:
                await self.transition(AgentState.TERMINATING, event)
                break

    async def _handle_event_error(self, error: Exception, event: StateTransitionEvent):
        """Error handling with circuit breakers"""
        error_handler = self._state_cache[self._current_state]
        await error_handler.on_error(error, event)

# ======================
# State Handlers
# ======================

class StateHandler:
    def __init__(self, machine: AgentStateMachine):
        self.machine = machine
        self.redis = machine.redis

    async def on_enter(self, event: StateTransitionEvent):
        pass

    async def on_exit(self):
        pass

    async def handle_event(self, event: StateTransitionEvent):
        pass

    async def on_error(self, error: Exception, event: StateTransitionEvent):
        pass

@AgentStateMachine.register_state_handler(AgentState.BOOTSTRAP)
class BootstrapStateHandler(StateHandler):
    async def on_enter(self, event):
        await self.initialize_agent()

    @circuit(failure_threshold=3)
    async def initialize_agent(self):
        # Implementation details
        pass

@AgentStateMachine.register_state_handler(AgentState.ACTIVE)
class ActiveStateHandler(StateHandler):
    async def handle_event(self, event):
        if event.event_type == "agent.task.assignment":
            await self.process_task(event.payload)
    
    async def process_task(self, task):
        # Task processing logic
        pass

# ======================
# Transition Definitions
# ======================

AgentStateMachine.register_transition(
    StateTransition(
        source=AgentState.BOOTSTRAP,
        target=AgentState.SYNCING,
        guard=lambda e: e.payload.get('cluster_ready', False),
        after_transition=lambda: log_audit_event("Bootstrap completed")
    )
)

AgentStateMachine.register_transition(
    StateTransition(
        source=AgentState.SYNCING,
        target=AgentState.ACTIVE,
        before_transition=lambda: validate_consensus(),
        after_transition=lambda: notify_cluster_members()
    )
)

# ======================
# Error Handling
# ======================

class IllegalStateTransitionError(Exception):
    """Raised for invalid state transitions"""

class GuardConditionFailedError(Exception):
    """Raised when transition guard fails"""

class RecoverableError(Exception):
    """Temporary errors with retry capability"""

class FatalError(Exception):
    """Unrecoverable critical errors"""

# ======================
# Plugin System
# ======================

class AuditPlugin:
    async def before_transition(self, machine, transition, event):
        await machine.redis.xadd(
            "audit:transitions",
            {"agent": machine.agent_id, "transition": f"{transition.source}->{transition.target}"}
        )

class MetricsPlugin:
    async def after_transition(self, machine, transition, event):
        machine.TRANSITION_COUNTER.labels(
            transition.source.name, 
            transition.target.name
        ).inc()

# ======================
# Initialization
# ======================

AgentStateMachine.register_plugin(AuditPlugin())
AgentStateMachine.register_plugin(MetricsPlugin())
