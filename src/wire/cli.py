from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

import click
import asyncio

from wire.app import app
from wire.config import settings
from wire.crypto import SecureRandom, hash_password


def create_cli_app(info: Any) -> Any:
    """Create app for CLI context."""
    # Return a dummy object for CLI compatibility
    return type('obj', (object,), {'name': 'wire'})


@click.group()
@click.version_option(version="2.0.0", prog_name="wire")
def cli() -> None:
    """Wire - Secure messaging platform for activists."""
    pass


@cli.command()
@click.option(
    "--host",
    "-h",
    default="127.0.0.1",
    help="The interface to bind to.",
)
@click.option(
    "--port",
    "-p",
    default=8000,
    help="The port to bind to.",
)
@click.option(
    "--reload",
    "-r",
    is_flag=True,
    help="Enable auto-reload.",
)
def run(host: str, port: int, reload: bool) -> None:
    """Run the development server."""
    import uvicorn
    
    uvicorn.run(
        "wire.app:app",
        host=host,
        port=port,
        reload=reload,
        log_level="info",
    )


@cli.command()
@click.option(
    "--workers",
    "-w",
    default=4,
    help="Number of worker processes.",
)
@click.option(
    "--bind",
    "-b",
    default="0.0.0.0:8000",
    help="The socket to bind.",
)
@click.option(
    "--access-log",
    is_flag=True,
    help="Enable access log.",
)
def serve(workers: int, bind: str, access_log: bool) -> None:
    """Run the production server with Uvicorn."""
    try:
        import uvicorn
    except ImportError:
        click.echo("Error: Uvicorn is not installed. Install it with: pip install 'uvicorn[standard]'")
        sys.exit(1)
    
    # Parse bind address
    if ":" in bind:
        host, port_str = bind.split(":", 1)
        port = int(port_str)
    else:
        host = bind
        port = 8000
    
    uvicorn.run(
        "wire.app:app",
        host=host,
        port=port,
        workers=workers,
        log_level="info" if access_log else "warning",
        access_log=access_log,
        loop="uvloop",
    )


@cli.group()
def db() -> None:
    """Database management commands."""
    pass


@db.command()
@click.confirmation_option(prompt="This will delete all data. Are you sure?")
def reset() -> None:
    """Reset the database (delete all data)."""
    import redis.asyncio as redis
    
    async def _reset_db():
        click.echo("Connecting to Redis...")
        r = await redis.from_url(settings.redis_url)
        
        click.echo("Flushing database...")
        await r.flushdb()
        
        await r.close()
        click.echo("Database reset successfully!")
    
    asyncio.run(_reset_db())


@db.command()
def info() -> None:
    """Show database information."""
    import redis.asyncio as redis
    
    async def _db_info():
        r = await redis.from_url(settings.redis_url)
        
        info = await r.info()
        click.echo(f"Redis version: {info['redis_version']}")
        click.echo(f"Connected clients: {info['connected_clients']}")
        click.echo(f"Used memory: {info['used_memory_human']}")
        click.echo(f"Keys: {await r.dbsize()}")
        
        await r.close()
    
    asyncio.run(_db_info())


@cli.group()
def user() -> None:
    """User management commands."""
    pass


@user.command()
@click.option("--username", "-u", prompt=True, help="Username")
@click.option("--email", "-e", prompt=True, help="Email address")
@click.option("--password", "-p", prompt=True, hide_input=True, confirmation_prompt=True, help="Password")
@click.option("--admin", is_flag=True, help="Make user an admin")
def create(username: str, email: str, password: str, admin: bool) -> None:
    """Create a new user."""
    from wire.models.async_user import AsyncUser as User, UserExists
    
    async def _create_user():
        try:
            user = User(username=username, email=email)
            user.set_password(password)
            user.is_admin = admin
            user.is_active = True
            await user.save()
            
            click.echo(f"User '{username}' created successfully!")
            if admin:
                click.echo("User has admin privileges.")
        except UserExists:
            click.echo(f"Error: User '{username}' already exists!", err=True)
            sys.exit(1)
        except Exception as e:
            click.echo(f"Error creating user: {e}", err=True)
            sys.exit(1)
    
    asyncio.run(_create_user())


@user.command()
@click.argument("username")
def delete(username: str) -> None:
    """Delete a user."""
    from wire.models.async_user import AsyncUser as User, UserNotFoundError
    
    async def _delete_user():
        try:
            user = await User.load_by_username(username)
            
            if click.confirm(f"Are you sure you want to delete user '{username}'?"):
                await user.delete()
                click.echo(f"User '{username}' deleted successfully!")
            else:
                click.echo("Deletion cancelled.")
        except UserNotFoundError:
            click.echo(f"Error: User '{username}' not found!", err=True)
            sys.exit(1)
        except Exception as e:
            click.echo(f"Error deleting user: {e}", err=True)
            sys.exit(1)
    
    asyncio.run(_delete_user())


@user.command()
@click.option("--format", "-f", type=click.Choice(["table", "json"]), default="table", help="Output format")
def list(format: str) -> None:
    """List all users."""
    import json
    import redis.asyncio as redis
    
    async def _list_users():
        r = await redis.from_url(settings.redis_url, decode_responses=True)
        
        # Get all user keys
        user_keys = []
        async for key in r.scan_iter(match="user:*", count=100):
            if not key.endswith(":contacts") and not key.endswith(":followers"):
                user_keys.append(key)
        
        users = []
        
        for key in user_keys:
            user_data = await r.hgetall(key)
            if user_data and "username" in user_data:
                users.append({
                    "username": user_data.get("username", ""),
                    "email": user_data.get("email", ""),
                    "active": user_data.get("is_active", "false") == "true",
                    "admin": user_data.get("is_admin", "false") == "true",
                })
        
        await r.close()
        
        if format == "json":
            click.echo(json.dumps(users, indent=2))
        else:
            if not users:
                click.echo("No users found.")
                return
            
            # Table format
            click.echo(f"{'Username':<20} {'Email':<30} {'Active':<8} {'Admin':<8}")
            click.echo("-" * 70)
            for user in users:
                click.echo(
                    f"{user['username']:<20} "
                    f"{user['email']:<30} "
                    f"{'Yes' if user['active'] else 'No':<8} "
                    f"{'Yes' if user['admin'] else 'No':<8}"
                )
    
    asyncio.run(_list_users())


@cli.group()
def security() -> None:
    """Security management commands."""
    pass


@security.command()
@click.option("--length", "-l", default=32, help="Length of the secret key")
def generate_secret(length: int) -> None:
    """Generate a new secret key."""
    secret = SecureRandom.generate_token(length)
    click.echo(f"Generated secret key: {secret}")
    click.echo("\nAdd this to your .env file:")
    click.echo(f"WIRE_SECRET_KEY={secret}")


@security.command()
def check() -> None:
    """Check security configuration."""
    issues = []
    
    # Check secret key
    if len(settings.secret_key.get_secret_value()) < 32:
        issues.append("❌ Secret key is too short (should be at least 32 characters)")
    else:
        click.echo("✅ Secret key is properly configured")
    
    # Check debug mode
    if settings.debug and settings.is_production():
        issues.append("❌ Debug mode is enabled in production")
    else:
        click.echo("✅ Debug mode is properly configured")
    
    # Check HTTPS
    if settings.is_production() and not settings.session_cookie_secure:
        issues.append("❌ Secure cookies are disabled in production")
    else:
        click.echo("✅ Cookie security is properly configured")
    
    # Check Redis password
    if settings.is_production() and not settings.redis_password:
        issues.append("⚠️  Redis password is not set (recommended for production)")
    else:
        click.echo("✅ Redis authentication is configured")
    
    # Check CSP
    if not settings.csp_enabled:
        issues.append("⚠️  Content Security Policy is disabled")
    else:
        click.echo("✅ Content Security Policy is enabled")
    
    # Summary
    if issues:
        click.echo("\n⚠️  Security issues found:")
        for issue in issues:
            click.echo(f"  {issue}")
    else:
        click.echo("\n✅ All security checks passed!")


@cli.command()
def init() -> None:
    """Initialize the application (create directories, etc)."""
    click.echo("Initializing Wire application...")
    
    # Create upload directories
    upload_dirs = [
        settings.upload_path,
        settings.upload_avatars_path,
        settings.upload_images_path,
    ]
    
    for dir_path in upload_dirs:
        dir_path.mkdir(parents=True, exist_ok=True)
        click.echo(f"✅ Created directory: {dir_path}")
    
    # Create .env file if it doesn't exist
    env_file = Path(".env")
    if not env_file.exists():
        secret = SecureRandom.generate_token(32)
        env_content = f"""# Wire Configuration
WIRE_SECRET_KEY={secret}
WIRE_DEBUG=false
WIRE_ENVIRONMENT=production

# Redis Configuration
WIRE_REDIS_HOST=localhost
WIRE_REDIS_PORT=6379
WIRE_REDIS_DB=0
# WIRE_REDIS_PASSWORD=your-redis-password

# Security
WIRE_SESSION_COOKIE_SECURE=true
WIRE_CSRF_ENABLED=true
"""
        env_file.write_text(env_content)
        click.echo("✅ Created .env file with default configuration")
    else:
        click.echo("ℹ️  .env file already exists")
    
    # Test Redis connection
    async def _test_redis():
        try:
            import redis.asyncio as redis
            r = await redis.from_url(settings.redis_url)
            await r.ping()
            await r.close()
            click.echo("✅ Redis connection successful")
        except Exception as e:
            click.echo(f"❌ Redis connection failed: {e}", err=True)
    
    asyncio.run(_test_redis())
    
    click.echo("\n✨ Wire application initialized successfully!")
    click.echo("Run 'wire run' to start the development server.")


def main() -> None:
    """Main entry point."""
    cli()


if __name__ == "__main__":
    main()