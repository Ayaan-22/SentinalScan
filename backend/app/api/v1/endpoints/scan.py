
from fastapi import APIRouter, Depends, HTTPException

from app.core.security import get_api_key
from app.models.policy import PolicyAuthorization, StoredPolicy
from app.models.scan import ScanRequest, ScanResponse
from app.services.scanner.authorization import principal_for_key
from app.services.scanner.manager import scan_manager

router = APIRouter()

@router.get("/", response_model=list[ScanResponse], dependencies=[Depends(get_api_key)])
async def list_scans():
    """
    List all scan sessions, sorted by start time (newest first).
    """
    return scan_manager.get_all_scans()

@router.post("/", response_model=ScanResponse, dependencies=[Depends(get_api_key)])
async def start_scan(request: ScanRequest, api_key: str = Depends(get_api_key)):
    """
    Start a new vulnerability scan.
    Returns immediately with a scan_id. Monitor progress via GET /{scan_id}
    or stream logs via WebSocket at /ws/logs/{scan_id}.
    """
    try:
        return await scan_manager.create_scan(request, principal_for_key(api_key))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))

@router.post("/policies", response_model=StoredPolicy)
async def authorize_policy(request: PolicyAuthorization, api_key: str = Depends(get_api_key)):
    """Explicitly authorize and durably store an immutable version-1 active policy."""
    try:
        return scan_manager.authorization_store.register(request, principal_for_key(api_key))
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))


@router.get("/policies/{policy_id}", response_model=StoredPolicy, dependencies=[Depends(get_api_key)])
async def get_policy(policy_id: str):
    try:
        return scan_manager.authorization_store.get(policy_id)
    except PermissionError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/{scan_id}/requests", response_model=list[dict], dependencies=[Depends(get_api_key)])
async def get_request_audit(scan_id: str):
    """Durable metadata-only request trail, also readable after an API restart."""
    return scan_manager.authorization_store.requests_for_scan(scan_id)


@router.get("/{scan_id}", response_model=ScanResponse, dependencies=[Depends(get_api_key)])
async def get_scan_status(scan_id: str):
    """
    Get the status of a specific scan.
    """
    scan = scan_manager.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan.recent_logs = scan_manager.get_logs(scan_id)[-300:]
    return scan

@router.get("/{scan_id}/logs", response_model=list[dict], dependencies=[Depends(get_api_key)])
async def get_scan_logs(scan_id: str):
    """
    Get logs for a specific scan.
    """
    return scan_manager.get_logs(scan_id)

@router.post("/{scan_id}/stop", response_model=ScanResponse, dependencies=[Depends(get_api_key)])
async def stop_scan(scan_id: str):
    """
    Stop a running scan.
    """
    scan = scan_manager.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    await scan_manager.stop_scan(scan_id)
    return scan
