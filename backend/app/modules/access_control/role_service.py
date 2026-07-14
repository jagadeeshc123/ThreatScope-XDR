import json
from pathlib import Path

from sqlalchemy.orm import Session

from .models import AccessPermission, AccessRole, RolePermissionAssignment, UserAccount, UserRoleAssignment


_RULES = Path(__file__).with_name("rules")


def seed_roles_and_permissions(db: Session) -> None:
    catalog = json.loads((_RULES / "permissions.json").read_text(encoding="utf-8"))
    for key, name, category in catalog:
        item = db.query(AccessPermission).filter_by(permission_key=key).first()
        if not item:
            db.add(AccessPermission(permission_key=key, name=name, description=name, category=category))
    db.flush()
    permissions = {item.permission_key: item for item in db.query(AccessPermission).all()}
    definitions = json.loads((_RULES / "default_roles.json").read_text(encoding="utf-8"))
    for key, definition in definitions.items():
        role = db.query(AccessRole).filter_by(role_key=key).first()
        if not role:
            role = AccessRole(role_key=key, name=definition["name"], description=definition["description"], system_role=True)
            db.add(role)
            db.flush()
        else:
            role.name = definition["name"]
            role.description = definition["description"]
            role.system_role = True
            role.enabled = True
        desired = set(permissions) if definition["permissions"] == ["*"] else set(definition["permissions"])
        current = {assignment.permission.permission_key: assignment for assignment in role.permissions}
        for permission_key in desired - set(current):
            db.add(RolePermissionAssignment(role_id=role.id, permission_id=permissions[permission_key].id))
        for permission_key, assignment in current.items():
            if permission_key not in desired:
                db.delete(assignment)
    db.commit()


def effective_permissions(db: Session, user: UserAccount) -> set[str]:
    if user.is_system_admin:
        return {row.permission_key for row in db.query(AccessPermission.permission_key).all()}
    rows = (
        db.query(AccessPermission.permission_key)
        .join(RolePermissionAssignment, RolePermissionAssignment.permission_id == AccessPermission.id)
        .join(AccessRole, AccessRole.id == RolePermissionAssignment.role_id)
        .join(UserRoleAssignment, UserRoleAssignment.role_id == AccessRole.id)
        .filter(UserRoleAssignment.user_id == user.id, AccessRole.enabled.is_(True))
        .all()
    )
    return {row[0] for row in rows}


def role_keys(db: Session, user_id: int) -> list[str]:
    rows = (
        db.query(AccessRole.role_key)
        .join(UserRoleAssignment, UserRoleAssignment.role_id == AccessRole.id)
        .filter(UserRoleAssignment.user_id == user_id, AccessRole.enabled.is_(True))
        .order_by(AccessRole.role_key)
        .all()
    )
    return [row[0] for row in rows]


def assign_roles(db: Session, user: UserAccount, keys: list[str], actor_id: int | None = None) -> None:
    roles = db.query(AccessRole).filter(AccessRole.role_key.in_(set(keys)), AccessRole.enabled.is_(True)).all() if keys else []
    if len(roles) != len(set(keys)):
        raise ValueError("One or more roles are invalid or disabled")
    db.query(UserRoleAssignment).filter_by(user_id=user.id).delete(synchronize_session=False)
    for role in roles:
        db.add(UserRoleAssignment(user_id=user.id, role_id=role.id, assigned_by_user_id=actor_id))
    db.flush()

