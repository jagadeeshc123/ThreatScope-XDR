"""Authentication-aware HTTP helpers shared by all module regression tests."""

from app.modules.access_control.models import AccessRole, AuthSession, UserAccount
from app.modules.access_control.role_service import seed_roles_and_permissions
from app.modules.access_control.user_service import create_user


TEST_ADMIN_USERNAME = "test.admin"
TEST_ADMIN_PASSWORD = "Correct-Horse-Battery-74!"


def authenticate_admin(client, session_factory):
    client.cookies.clear()
    client.headers.pop("X-CSRF-Token", None)
    with session_factory() as db:
        seed_roles_and_permissions(db)
        if not db.query(UserAccount).filter_by(username_normalized=TEST_ADMIN_USERNAME).first():
            create_user(
                db,
                username=TEST_ADMIN_USERNAME,
                display_name="Test Administrator",
                email="test-admin@example.test",
                password=TEST_ADMIN_PASSWORD,
                role_keys=["administrator"],
                must_change_password=False,
                is_system_admin=True,
            )
    response = client.post("/api/auth/login", json={"username": TEST_ADMIN_USERNAME, "password": TEST_ADMIN_PASSWORD})
    if response.status_code != 200:
        raise AssertionError(f"Test administrator login failed: {response.status_code} {response.text}")
    csrf = client.get("/api/auth/csrf")
    if csrf.status_code != 200:
        raise AssertionError(f"Test CSRF retrieval failed: {csrf.status_code} {csrf.text}")
    client.headers.update({"X-CSRF-Token": csrf.json()["csrf_token"]})
    return response.json()["user"]


def authenticated_get(client, path, **kwargs):
    return client.get(path, **kwargs)


def authenticated_mutation(client, method, path, **kwargs):
    return client.request(method, path, **kwargs)


def revoke_all_sessions(session_factory, user_id):
    with session_factory() as db:
        db.query(AuthSession).filter_by(user_id=user_id).update({AuthSession.revoked_at: AuthSession.created_at}, synchronize_session=False)
        db.commit()


def permission_assertion(response, allowed=True):
    expected = range(200, 300) if allowed else (401, 403)
    if response.status_code not in expected:
        raise AssertionError(f"Unexpected authorization result: {response.status_code} {response.text}")
