from fastapi import APIRouter

from app.api.v1.routes import (
    api_keys,
    audit_logs,
    auth,
    chat,
    files,
    internal,
    knowledge_bases,
    llm,
    llm_budgets,
    llm_usage,
    public_api,
    roles,
    users,
)

router = APIRouter()
router.include_router(auth.router, prefix="/auth", tags=["authentication"])
router.include_router(users.router, prefix="/users", tags=["users"])
router.include_router(roles.router, prefix="/roles", tags=["roles"])
router.include_router(roles.permission_router, prefix="/permissions", tags=["permissions"])
router.include_router(roles.limit_router, prefix="/limits", tags=["limits"])
router.include_router(files.router, prefix="/files", tags=["files"])
router.include_router(
    knowledge_bases.router,
    prefix="/knowledge-bases",
    tags=["knowledge-bases"],
)
router.include_router(chat.router, prefix="/chat", tags=["chat"])
router.include_router(api_keys.router, prefix="/api-keys", tags=["api-keys"])
router.include_router(audit_logs.router, prefix="/audit-logs", tags=["audit-logs"])
router.include_router(llm.router, prefix="/llm/providers", tags=["llm-providers"])
router.include_router(llm_usage.router, prefix="/llm/usage", tags=["llm-usage"])
router.include_router(
    llm_budgets.router,
    prefix="/llm/budget-policies",
    tags=["llm-budgets"],
)
router.include_router(public_api.router, prefix="/public", tags=["public-api"])
router.include_router(internal.router, prefix="/internal", tags=["internal"])
