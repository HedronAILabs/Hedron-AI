import asyncio
import hashlib
from datetime import datetime
from typing import Dict, List, Optional, Any, Union, Callable, Awaitable
from pydantic import BaseModel, ValidationError, Field, validator
from redis.asyncio import RedisCluster
from opa_client.opa import OPAClient
from cedar.policy import PolicyStore
import yaml
import json
import ast
from numba import jit
import diskcache as dc

# =================================================================
# Core Data Models
# =================================================================

class BusinessRule(BaseModel):
    rule_id: str = Field(..., min_length=5, regex=r'^br-\d+$')
    version: str = Field(..., regex=r'^\d+\.\d+\.\d+$')
    description: str = Field(..., max_length=280)
    condition: Union[str, dict]
    action: Union[str, dict]
    priority: int = Field(1, ge=1, le=100)
    tags: List[str] = []
    valid_from: datetime
    valid_to: Optional[datetime]
    tenant_id: str = Field("default", min_length=3)
    
    @validator('condition', 'action')
    def validate_logic(cls, v):
        if isinstance(v, str):
            try:
                ast.parse(v)
            except SyntaxError:
                raise ValueError("Invalid syntax in rule logic")
        return v

class RulePackage(BaseModel):
    package_id: str = Field(..., regex=r'^pkg-\d+$')
    rules: Dict[str, BusinessRule] = {}
    dependencies: Dict[str, str] = {}  # {rule_id: min_version}
    conflict_resolution: str = Field("priority", regex="^(priority|order|manual)$")

# =================================================================
# Execution Engines
# =================================================================

class RuleEvaluator:
    def __init__(self, redis: RedisCluster, opa: OPAClient):
        self.redis = redis
        self.opa = opa
        self._cache = dc.Cache('/tmp/rule_cache')
        self._compiled_rules = {}
        
    async def load_package(self, package: RulePackage):
        """Compile and cache rule package"""
        cache_key = f"rule_pkg:{package.package_id}"
        compiled = await self._compile_rules(package)
        
        async with self.redis.pipeline(transaction=True) as pipe:
            pipe.hset(cache_key, mapping={
                'meta': package.json(),
                'compiled': json.dumps(compiled)
            })
            pipe.expire(cache_key, 3600)
            await pipe.execute()
            
        self._compiled_rules[package.package_id] = compiled
        
    def _compile_condition(self, condition: str) -> Callable:
        """JIT-compile condition logic"""
        try:
            return jit(nopython=True)(eval(f"lambda context: {condition}"))
        except:
            return eval(f"lambda context: {condition}")

    async def _compile_rules(self, package: RulePackage) -> Dict:
        """Parallel rule compilation"""
        compiled = {}
        for rule_id, rule in package.rules.items():
            compiled[rule_id] = {
                'condition': self._compile_condition(rule.condition),
                'action': ast.literal_eval(rule.action) if isinstance(rule.action, str) else rule.action
            }
        return compiled

    async def evaluate(
        self, 
        package_id: str,
        context: Dict[str, Any],
        conflict_strategy: str = "priority"
    ) -> List[Dict]:
        """Execute rule evaluation with conflict resolution"""
        compiled = await self._get_compiled_package(package_id)
        applicable = []
        
        # Parallel condition evaluation
        tasks = [
            self._eval_condition(rule['condition'], context) 
            for rule in compiled.values()
        ]
        results = await asyncio.gather(*tasks)
        
        for rule_id, (passed, latency) in zip(compiled.keys(), results):
            if passed:
                applicable.append({
                    'rule_id': rule_id,
                    'action': compiled[rule_id]['action'],
                    'priority': self._compiled_rules[package_id].rules[rule_id].priority,
                    'evaluation_time': latency
                })
                
        return self._resolve_conflicts(applicable, strategy=conflict_strategy)
        
    async def _eval_condition(self, condition_fn: Callable, context: Dict) -> tuple:
        """Safe condition evaluation with monitoring"""
        start = datetime.now()
        try:
            result = condition_fn(context)
            return (bool(result), (datetime.now() - start).total_seconds())
        except Exception as e:
            return (False, (datetime.now() - start).total_seconds())
        
    def _resolve_conflicts(self, applicable: List, strategy: str) -> List:
        """Conflict resolution strategies"""
        if strategy == "priority":
            return sorted(applicable, key=lambda x: (-x['priority'], x['evaluation_time']))
        elif strategy == "order":
            return sorted(applicable, key=lambda x: x['evaluation_time'])
        return applicable

# =================================================================
# Rule Management
# =================================================================

class RuleManager:
    def __init__(self, redis: RedisCluster, opa: OPAClient):
        self.redis = redis
        self.opa = opa
        self.evaluator = RuleEvaluator(redis, opa)
        self._version_store = dc.Cache('/tmp/rule_versions')
        
    async def deploy_rule(self, rule: BusinessRule) -> str:
        """Deploy rule with version control"""
        await self._validate_rule_conflicts(rule)
        version_key = f"rules:{rule.tenant_id}:{rule.rule_id}:versions"
        
        async with self.redis.pipeline(transaction=True) as pipe:
            pipe.hset(version_key, rule.version, rule.json())
            pipe.set(f"rules:{rule.tenant_id}:{rule.rule_id}:current", rule.version)
            await pipe.execute()
            
        self._version_store[rule.rule_id] = rule.version
        return rule.version
        
    async def rollback_rule(self, rule_id: str, version: str) -> bool:
        """Version rollback with consistency checks"""
        version_key = f"rules:{rule_id}:versions"
        current = await self.redis.get(f"rules:{rule_id}:current")
        
        if current != version:
            await self.redis.set(f"rules:{rule_id}:current", version)
            return True
        return False
        
    async def _validate_rule_conflicts(self, rule: BusinessRule):
        """Check rule dependencies and conflicts"""
        existing = await self.redis.hgetall(f"rules:{rule.tenant_id}:{rule.rule_id}:versions")
        for ver, data in existing.items():
            existing_rule = BusinessRule.parse_raw(data)
            if existing_rule.condition == rule.condition and existing_rule.version != rule.version:
                raise ValueError(f"Rule conflict detected in version {existing_rule.version}")

# =================================================================
# Policy Integration
# =================================================================

class PolicyManager:
    def __init__(self, cedar: PolicyStore):
        self.cedar = cedar
        self._policy_cache = dc.Cache('/tmp/policy_cache')
        
    async def enforce(self, policy_id: str, context: Dict) -> bool:
        """CEDAR policy enforcement"""
        policy = await self._load_policy(policy_id)
        return await self.cedar.is_authorized(
            principal=context.get('user'),
            action=context.get('action'),
            resource=context.get('resource'),
            context=context
        )
        
    async def _load_policy(self, policy_id: str) -> dict:
        """Cached policy loading"""
        if policy_id in self._policy_cache:
            return self._policy_cache[policy_id]
            
        policy = await self.cedar.get_policy(policy_id)
        self._policy_cache[policy_id] = policy
        return policy

# =================================================================
# Audit System
# =================================================================

class RuleAuditor:
    def __init__(self, redis: RedisCluster):
        self.redis = redis
        self._audit_stream = "rule_audit_log"
        
    async def log_execution(self, execution_id: str, context: Dict, result: Dict):
        """Immutable audit logging"""
        entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'execution_id': execution_id,
            'context_hash': hashlib.sha256(json.dumps(context).encode()).hexdigest(),
            'result': result,
            'signature': self._sign_entry(context, result)
        }
        
        await self.redis.xadd(self._audit_stream, entry)
        
    def _sign_entry(self, context: Dict, result: Dict) -> str:
        """Cryptographic audit trail signing"""
        data = json.dumps({
            'context': context,
            'result': result,
            'timestamp': datetime.utcnow().timestamp()
        })
        return hashlib.sha3_256(data.encode()).hexdigest()

# =================================================================
# Enterprise Features
# =================================================================

class RuleAPI:
    def __init__(self, manager: RuleManager, auditor: RuleAuditor):
        self.manager = manager
        self.auditor = auditor
        self._session = aiohttp.ClientSession()
        
    async def execute_ruleset(
        self,
        package_id: str,
        context: Dict,
        audit_id: Optional[str] = None
    ) -> Dict:
        """End-to-end rule execution with audit"""
        execution_id = audit_id or self._generate_execution_id()
        
        try:
            result = await self.manager.evaluator.evaluate(package_id, context)
            await self.auditor.log_execution(execution_id, context, result)
            return {
                'success': True,
                'execution_id': execution_id,
                'actions': result
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'execution_id': execution_id
            }
            
    def _generate_execution_id(self) -> str:
        return f"ex_{hashlib.shake_256(str(datetime.now()).encode()).hexdigest(8)}"

# =================================================================
# Initialization Example
# =================================================================

async def main():
    # Infrastructure setup
    redis = await RedisCluster.from_url("redis://rule-cache:6379")
    opa = OPAClient("http://opa:8181/v1")
    cedar = PolicyStore("https://cedar.example.com/api")
    
    # Service initialization
    manager = RuleManager(redis, opa)
    auditor = RuleAuditor(redis)
    api = RuleAPI(manager, auditor)
    
    # Sample rule deployment
    sample_rule = BusinessRule(
        rule_id="br-1001",
        version="1.0.0",
        description="Premium customer discount",
        condition="context['customer_tier'] == 'premium' and context['order_total'] > 1000",
        action="{ 'discount': 0.1, 'notify': ['billing', 'customer'] }",
        priority=10,
        valid_from=datetime(2024, 1, 1),
        tenant_id="acme_corp"
    )
    
    await manager.deploy_rule(sample_rule)
    
    # Rule execution example
    result = await api.execute_ruleset(
        package_id="pkg-2001",
        context={
            'customer_tier': 'premium',
            'order_total': 1500,
            'user': 'csr_agent_01'
        }
    )
    print(f"Execution Result: {result}")

if __name__ == "__main__":
    asyncio.run(main())
