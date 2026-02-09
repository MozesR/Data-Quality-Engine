import importlib.util
import os
from pathlib import Path


def load_app_module():
    # Ensure test DB is used before importing module.
    os.environ["DATABASE_URL"] = "sqlite+pysqlite:///:memory:"
    os.environ["AUTH_MODE"] = "demo"
    os.environ["AUTH_REQUIRED"] = "false"
    os.environ["AUTH_SECRET"] = "test-secret"
    os.environ["JWT_ISSUER"] = "test-issuer"
    os.environ["JWT_AUDIENCE"] = "test-aud"

    main_path = Path(__file__).resolve().parents[1] / "services" / "mcp-server" / "app" / "main.py"
    spec = importlib.util.spec_from_file_location("mcp_main", str(main_path))
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[attr-defined]
    return module


def test_refresh_token_rotation_and_access_revocation():
    main = load_app_module()
    main.ensure_tables()

    # Create a user.
    with main.engine.begin() as conn:
        conn.execute(
            main.users.insert().values(
                email="u@example.com",
                name="U",
                password_hash=main.password_hash("Password123!"),
                role="user",
                team="default",
                is_active=True,
                created_at=main.utcnow(),
                last_login_at=None,
            )
        )
        uid = conn.execute(main.text("SELECT id FROM users WHERE email = :e"), {"e": "u@example.com"}).scalar_one()

    rt1 = main.make_refresh_token(int(uid))
    rotated = main.rotate_refresh_token(rt1)
    assert rotated is not None
    uid2, rt2 = rotated
    assert uid2 == int(uid)
    assert rt2 != rt1

    # Old refresh token can't be reused.
    assert main.rotate_refresh_token(rt1) is None

    # Access token can be revoked via jti blacklist.
    user_row = {"id": int(uid), "email": "u@example.com", "role": "user", "team": "default", "name": "U"}
    at = main.make_access_token(user_row)
    payload = main.parse_access_token(at)
    assert payload is not None
    jti = payload["jti"]
    exp_ts = int(payload["exp"])
    main.revoke_access_token(jti, int(uid), main.datetime.fromtimestamp(exp_ts, tz=main.timezone.utc))
    assert main.parse_access_token(at) is None
