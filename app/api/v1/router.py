from fastapi import APIRouter

from app.api.v1.routes import auth, files, internal, roles, users

router = APIRouter()
router.include_router(auth.router, prefix="/auth", tags=["authentication"])
router.include_router(users.router, prefix="/users", tags=["users"])
router.include_router(roles.router, prefix="/roles", tags=["roles"])
router.include_router(roles.permission_router, prefix="/permissions", tags=["permissions"])
router.include_router(roles.limit_router, prefix="/limits", tags=["limits"])
router.include_router(files.router, prefix="/files", tags=["files"])
router.include_router(internal.router, prefix="/internal", tags=["internal"])
