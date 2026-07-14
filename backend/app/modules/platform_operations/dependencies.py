"""Named operation dependencies kept beside the operations router."""
from app.modules.access_control.dependencies import require_permission

view_operations = require_permission("operations:view")
diagnose_operations = require_permission("operations:diagnostics")
manage_backups = require_permission("operations:backup")
manage_restores = require_permission("operations:restore")
