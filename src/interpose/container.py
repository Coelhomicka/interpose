from __future__ import annotations

from dataclasses import dataclass

from .config import RuntimeConfig
from .core.audit import AuditLogger
from .core.policies import PolicyEngine, SQLitePolicyRepository
from .core.redaction import SecretRedactionEngine
from .executor.trusted_executor import TrustedExecutor
from .secrets.encrypted_local import EncryptedLocalSecretStore
from .session.launcher import SessionLauncher


@dataclass(frozen=True)
class RuntimeContainer:
    config: RuntimeConfig
    secret_store: EncryptedLocalSecretStore
    policy_repository: SQLitePolicyRepository
    policy_engine: PolicyEngine
    audit_logger: AuditLogger
    redaction_engine: SecretRedactionEngine
    executor: TrustedExecutor
    session_launcher: SessionLauncher


def create_container(config: RuntimeConfig | None = None) -> RuntimeContainer:
    runtime_config = config or RuntimeConfig.from_env()
    secret_store = EncryptedLocalSecretStore(runtime_config.paths.database, runtime_config.master_key)
    policy_repository = SQLitePolicyRepository(runtime_config.paths.database)
    policy_engine = PolicyEngine(policy_repository)
    audit_logger = AuditLogger(runtime_config.paths.audit_database)
    redaction_engine = SecretRedactionEngine()
    executor = TrustedExecutor(
        secret_store=secret_store,
        policy_engine=policy_engine,
        audit_logger=audit_logger,
        redaction_engine=redaction_engine,
        agent_name=runtime_config.agent_name,
    )
    session_launcher = SessionLauncher(
        secret_store=secret_store,
        audit_logger=audit_logger,
        runtime_home=runtime_config.paths.home,
    )
    return RuntimeContainer(
        config=runtime_config,
        secret_store=secret_store,
        policy_repository=policy_repository,
        policy_engine=policy_engine,
        audit_logger=audit_logger,
        redaction_engine=redaction_engine,
        executor=executor,
        session_launcher=session_launcher,
    )
