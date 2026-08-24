from __future__ import annotations

import json
from pathlib import Path

import typer
import uvicorn

from ..api.app import create_app
from ..container import create_container
from ..core.policies import PolicyDocument, PolicyError
from ..core.references import SecretReferenceError, normalize_secret_reference
from ..executor.trusted_executor import ExecutionPreparationError, PolicyViolationError
from ..proxy.http_proxy import create_proxy_app
from ..secrets.base import SecretNotFound
from ..session.dotenv import DotenvValidationError, validate_dotenv
from ..session.isolation.base import IsolationError
from ..session.isolation.factory import create_isolation_backend
from ..session.launcher import SessionLaunchError
from ..session.profile import SessionProfile, SessionProfileError

app = typer.Typer(add_completion=False, help="Administrative CLI for Interpose")
secret_app = typer.Typer(add_completion=False, help="Secret management commands")
profile_app = typer.Typer(add_completion=False, help="Session profile commands")
env_app = typer.Typer(add_completion=False, help="Reference-only .env commands")
policy_app = typer.Typer(add_completion=False, help="Policy administration commands")
isolation_app = typer.Typer(add_completion=False, help="Process and network isolation commands")
interpose_exec_app = typer.Typer(
    add_completion=False,
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True},
    help="Trusted executor for untrusted commands",
)

app.add_typer(secret_app, name="secret")
app.add_typer(profile_app, name="profile")
app.add_typer(env_app, name="env")
app.add_typer(policy_app, name="policy")
app.add_typer(isolation_app, name="isolation")


def _container():
    return create_container()


@secret_app.command("add")
def secret_add(reference: str) -> None:
    container = _container()
    secret_value = typer.prompt("Secret", hide_input=True)
    try:
        normalized_reference = normalize_secret_reference(reference)
        metadata = container.secret_store.store(normalized_reference, secret_value)
    except SecretReferenceError as exc:
        typer.echo(f"Invalid secret reference: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo("Secret stored:")
    typer.echo(metadata.reference)


@secret_app.command("list")
def secret_list() -> None:
    container = _container()
    typer.echo("NAME")
    for metadata in container.secret_store.list_metadata():
        typer.echo(metadata.reference.removeprefix("secret://"))


@secret_app.command("delete")
def secret_delete(identifier: str) -> None:
    container = _container()
    target: str | int
    if identifier.isdigit():
        target = int(identifier)
    else:
        try:
            target = normalize_secret_reference(identifier)
        except SecretReferenceError as exc:
            typer.echo(f"Invalid secret reference: {exc}", err=True)
            raise typer.Exit(code=1) from exc
    if not container.secret_store.delete(target):
        raise typer.Exit(code=1)


@secret_app.command("inspect")
def secret_inspect(identifier: str) -> None:
    container = _container()
    metadata = None
    if identifier.isdigit():
        target_id = int(identifier)
        metadata = next((item for item in container.secret_store.list_metadata() if item.id == target_id), None)
    else:
        try:
            reference = normalize_secret_reference(identifier)
        except SecretReferenceError as exc:
            typer.echo(f"Invalid secret reference: {exc}", err=True)
            raise typer.Exit(code=1) from exc
        metadata = next((item for item in container.secret_store.list_metadata() if item.reference == reference), None)
    if metadata is None:
        raise typer.Exit(code=1)
    typer.echo(json.dumps(
        {
            "id": metadata.id,
            "reference": metadata.reference,
            "provider": metadata.provider,
            "namespace": metadata.namespace,
            "path": metadata.path,
            "fingerprint": metadata.fingerprint,
            "created_at": metadata.created_at.isoformat(),
            "updated_at": metadata.updated_at.isoformat(),
        },
        indent=2,
    ))


@profile_app.command("validate")
def profile_validate(path: Path) -> None:
    try:
        profile = SessionProfile.from_path(path)
        _container().session_launcher.validate_bindings(profile)
    except (SessionProfileError, SessionLaunchError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Profile valid: {path}")


@profile_app.command("env")
def profile_environment(path: Path) -> None:
    try:
        profile = SessionProfile.from_path(path)
    except SessionProfileError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    for name, reference in sorted(profile.environment.items()):
        typer.echo(f"{name}={reference}")


@env_app.command("validate")
def env_validate(
    path: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True),
    profile: Path = typer.Option(..., exists=True, dir_okay=False, readable=True),
) -> None:
    try:
        session_profile = SessionProfile.from_path(profile)
        validate_dotenv(path, session_profile)
    except (SessionProfileError, DotenvValidationError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Reference-only environment valid: {path}")


@policy_app.command("add")
def policy_add(path: Path) -> None:
    try:
        document = PolicyDocument.from_yaml(path.read_text(encoding="utf-8"))
        record = _container().policy_repository.store(document)
    except (OSError, PolicyError) as exc:
        typer.echo(f"Invalid policy: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Policy stored: {record.id} {record.secret_reference}")


@policy_app.command("list")
def policy_list() -> None:
    typer.echo("ID SECRET")
    for record in _container().policy_repository.list():
        typer.echo(f"{record.id} {record.secret_reference}")


@policy_app.command("delete")
def policy_delete(policy_id: int) -> None:
    if not _container().policy_repository.delete(policy_id):
        typer.echo("Policy not found", err=True)
        raise typer.Exit(code=1)


@policy_app.command("inspect")
def policy_inspect(policy_id: int) -> None:
    record = _container().policy_repository.get(policy_id)
    if record is None:
        typer.echo("Policy not found", err=True)
        raise typer.Exit(code=1)
    typer.echo(record.definition)


@isolation_app.command("doctor")
def isolation_doctor(
    profile: Path = typer.Option(..., exists=True, dir_okay=False, readable=True),
) -> None:
    try:
        session_profile = SessionProfile.from_path(profile)
        container = _container()
        backend = create_isolation_backend(
            session_profile.runtime.isolation,
            session="doctor",
            runtime_home=container.config.paths.home,
        )
    except (SessionProfileError, IsolationError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc

    doctor = getattr(backend, "doctor", None)
    if doctor is None:
        typer.echo("FAIL isolation: profile does not enable an enforced isolation backend", err=True)
        raise typer.Exit(code=1)
    checks = doctor()
    for name, passed, detail in checks:
        typer.echo(f"{'PASS' if passed else 'FAIL'} {name}: {detail}")
    if not all(passed for _, passed, _ in checks):
        raise typer.Exit(code=1)


@app.command(
    "run",
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True},
)
def run_session(
    ctx: typer.Context,
    profile: Path = typer.Option(..., exists=True, dir_okay=False, readable=True),
    agent: str = typer.Option("unknown", help="Agent or IDE identity"),
    session: str | None = typer.Option(None, help="Optional session identifier"),
    cwd: Path | None = typer.Option(None, exists=True, file_okay=False),
) -> None:
    try:
        session_profile = SessionProfile.from_path(profile)
        return_code = _container().session_launcher.run(
            list(ctx.args),
            profile=session_profile,
            agent=agent,
            session=session,
            cwd=cwd,
        )
    except (SessionProfileError, SessionLaunchError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    raise typer.Exit(code=return_code)


@app.command("api")
def run_api(host: str = "127.0.0.1", port: int = 8000) -> None:
    uvicorn.run(create_app(), host=host, port=port, log_level="info")


@app.command("proxy")
def run_proxy(host: str = "127.0.0.1", port: int = 9876) -> None:
    uvicorn.run(create_proxy_app(), host=host, port=port, log_level="info")


@interpose_exec_app.command()
def interpose_exec(
    ctx: typer.Context,
    agent: str = typer.Option("unknown", help="Agent identity"),
    destination: str | None = typer.Option(None, help="Explicit destination host"),
    method: str | None = typer.Option(None, help="Explicit method"),
    session: str = typer.Option("local", help="Session identifier"),
) -> None:
    command = list(ctx.args)
    container = _container()
    try:
        if destination:
            from ..models import DestinationContext

            destination_context = DestinationContext(host=destination, method=(method or "EXEC").upper())
        else:
            destination_context = None
        result = container.executor.execute(
            command,
            session=session,
            agent=agent,
            destination=destination_context,
        )
        if result.stdout:
            typer.echo(result.stdout, err=False, nl=False)
        if result.stderr:
            typer.echo(result.stderr, err=True, nl=False)
        raise typer.Exit(code=result.return_code)
    except (PolicyViolationError, ExecutionPreparationError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    except SecretNotFound as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
