from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from typing import List, Dict
from app.models.scan import ScanRequest, ScanResponse
from app.services.scanner.manager import scan_manager
from app.core.security import get_api_key

router = APIRouter()

@router.post("/", response_model=ScanResponse, dependencies=[Depends(get_api_key)])
async def start_scan(request: ScanRequest):
    """
    Start a new vulnerability scan.
    """
    try:
        return scan_manager.create_scan(request)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

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
