from sqlalchemy import inspect, text


USER_COLUMNS = {
    "registration_source": "VARCHAR(32) NOT NULL DEFAULT 'administrator'",
    "approved_at": "DATETIME",
    "approved_by_user_id": "INTEGER",
    "rejected_at": "DATETIME",
    "rejected_by_user_id": "INTEGER",
    "rejection_reason": "VARCHAR(500)",
    "terms_accepted_at": "DATETIME",
    "privacy_notice_version": "VARCHAR(64)",
    "email_verified": "BOOLEAN NOT NULL DEFAULT 0",
    "onboarding_completed_at": "DATETIME",
    "is_demo_account": "BOOLEAN NOT NULL DEFAULT 0",
}

MFA_DEVICE_COLUMNS = {
    "last_used_at": "DATETIME",
    "enrollment_expires_at": "DATETIME",
    "failed_attempts": "INTEGER NOT NULL DEFAULT 0",
}


def ensure_local_account_schema(engine) -> None:
    inspector = inspect(engine)
    if "user_accounts" not in inspector.get_table_names():
        return
    existing = {column["name"] for column in inspector.get_columns("user_accounts")}
    with engine.begin() as connection:
        for name, definition in USER_COLUMNS.items():
            if name not in existing:
                connection.execute(text(f"ALTER TABLE user_accounts ADD COLUMN {name} {definition}"))
        mfa_columns = {column["name"] for column in inspector.get_columns("mfa_devices")} if "mfa_devices" in inspector.get_table_names() else set()
        for name, definition in MFA_DEVICE_COLUMNS.items():
            if mfa_columns and name not in mfa_columns:
                connection.execute(text(f"ALTER TABLE mfa_devices ADD COLUMN {name} {definition}"))
        notification_columns = {column["name"] for column in inspector.get_columns("notifications")} if "notifications" in inspector.get_table_names() else set()
        if "recipient_user_id" not in notification_columns and notification_columns:
            connection.execute(text("ALTER TABLE notifications ADD COLUMN recipient_user_id INTEGER"))
        for statement in (
            "CREATE INDEX IF NOT EXISTS ix_user_accounts_registration_source ON user_accounts (registration_source)",
            "CREATE INDEX IF NOT EXISTS ix_user_accounts_created_at ON user_accounts (created_at)",
            "CREATE INDEX IF NOT EXISTS ix_notifications_recipient_user_id ON notifications (recipient_user_id)",
        ):
            connection.execute(text(statement))
