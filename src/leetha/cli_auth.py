"""CLI handlers for the 'leetha auth' subcommand."""
from __future__ import annotations

from pathlib import Path
from rich.console import Console
from rich.table import Table

from leetha.auth.tokens import (
    generate_token, hash_token,
    save_admin_token, load_admin_token, TokenWriteError,
)
from leetha.config import get_config
from leetha.store.database import Database

console = Console()


async def run_auth(args) -> None:
    """Dispatch auth subcommands."""
    action = getattr(args, "auth_action", None)
    if action is None:
        console.print("[yellow]Usage: leetha auth <show-token|reset-token|create-token|list-tokens|revoke-token>[/yellow]")
        return

    if action == "show-token":
        await _show_token()
    elif action == "reset-token":
        await _reset_token()
    elif action == "create-token":
        await _create_token(args.role, getattr(args, "label", None))
    elif action == "list-tokens":
        await _list_tokens()
    elif action == "revoke-token":
        await _revoke_token(args.id)


async def _show_token() -> None:
    token = load_admin_token()
    if token:
        console.print(f"[bold green]Admin token:[/bold green] {token}")
    else:
        console.print("[yellow]No admin token found at ~/.leetha/admin-token[/yellow]")
        console.print("Run [bold]leetha auth reset-token[/bold] to generate one.")


async def _reset_token() -> None:
    config = get_config()
    db = Database(Path(config.data_dir) / "leetha.db")
    await db.initialize()
    try:
        await db.revoke_all_admin_tokens()
        raw = generate_token()
        await db.create_auth_token(hash_token(raw), role="admin", label="cli-reset")
        try:
            save_admin_token(raw)
        except TokenWriteError as exc:
            console.print(f"[bold red]{exc}[/bold red]")
            return
        console.print("[bold green]Admin token regenerated:[/bold green]")
        console.print(f"[bold yellow]{raw}[/bold yellow]")
        console.print("[dim]Saved to ~/.leetha/admin-token[/dim]")
    finally:
        await db.close()


async def _create_token(role: str, label: str | None) -> None:
    config = get_config()
    db = Database(Path(config.data_dir) / "leetha.db")
    await db.initialize()
    try:
        raw = generate_token()
        token_id = await db.create_auth_token(hash_token(raw), role=role, label=label)
        console.print(f"[bold green]Token created (ID {token_id}, role={role}):[/bold green]")
        console.print(f"[bold yellow]{raw}[/bold yellow]")
        console.print("[dim]Save this token — it cannot be shown again.[/dim]")
    finally:
        await db.close()


async def _list_tokens() -> None:
    config = get_config()
    db = Database(Path(config.data_dir) / "leetha.db")
    await db.initialize()
    try:
        tokens = await db.list_auth_tokens()
        if not tokens:
            console.print("[yellow]No tokens found.[/yellow]")
            return
        table = Table(title="API Tokens")
        table.add_column("ID", style="cyan")
        table.add_column("Role", style="green")
        table.add_column("Label")
        table.add_column("Created")
        table.add_column("Last Used")
        table.add_column("Status")
        for t in tokens:
            status = "[red]REVOKED[/red]" if t["revoked"] else "[green]Active[/green]"
            table.add_row(
                str(t["id"]),
                t["role"],
                t.get("label") or "-",
                t["created_at"][:19],
                (t.get("last_used") or "-")[:19],
                status,
            )
        console.print(table)
    finally:
        await db.close()


async def _revoke_token(token_id: int) -> None:
    config = get_config()
    db = Database(Path(config.data_dir) / "leetha.db")
    await db.initialize()
    try:
        await db.revoke_auth_token(token_id)
        console.print(f"[bold red]Token {token_id} revoked.[/bold red]")
    finally:
        await db.close()
