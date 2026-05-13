from fastapi import APIRouter, Depends, HTTPException
from typing import List, Dict
from app.models.scan import ScanRequest, ScanResponse
from app.services.scanner.manager import scan_manager
from app.core.security import get_api_key

router = APIRouter()

@router.get("/", response_model=List[ScanResponse], dependencies=[Depends(get_api_key)])
async def list_scans():
    """
    List all scan sessions, sorted by start time (newest first).
    """
    return scan_manager.get_all_scans()

@router.post("/", response_model=ScanResponse, dependencies=[Depends(get_api_key)])
async def start_scan(request: ScanRequest):
    """
    Start a new vulnerability scan.
    Returns immediately with a scan_id. Monitor progress via GET /{scan_id}
    or stream logs via WebSocket at /ws/logs/{scan_id}.
    """
    try:
        return await scan_manager.create_scan(request)
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))

@router.get("/{scan_id}", response_model=ScanResponse, dependencies=[Depends(get_api_key)])
async def get_scan_status(scan_id: str):
    """
    Get the status of a specific scan.
    """
    scan = scan_manager.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan

@router.get("/{scan_id}/logs", response_model=List[Dict], dependencies=[Depends(get_api_key)])
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
    
    scan_manager.stop_scan(scan_id)
    return scan
