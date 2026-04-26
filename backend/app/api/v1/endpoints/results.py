from fastapi import APIRouter, Depends, HTTPException
from typing import List, Any
from app.models.vulnerability import Vulnerability
from app.services.scanner.manager import scan_manager
from app.core.security import get_api_key

router = APIRouter()

@router.get("/{scan_id}/results", response_model=List[Vulnerability], dependencies=[Depends(get_api_key)])
async def get_scan_results(scan_id: str):
    """
    Get the results (vulnerabilities) for a completed scan.
    """
    scan = scan_manager.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # In a real app, we'd fetch from DB. Here we check the in-memory object
    if hasattr(scan, 'results'):
        return scan.results
    
    return []
