from fastapi import APIRouter

from app.api.v1.endpoints import results, scan

api_router = APIRouter()
api_router.include_router(scan.router, prefix="/scan", tags=["scan"])
api_router.include_router(results.router, prefix="/scan", tags=["results"])
