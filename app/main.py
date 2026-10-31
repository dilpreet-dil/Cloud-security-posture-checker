import secrets
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Query
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import config, models, reporting, schemas
from .collectors import CollectorError
from .db import Base, engine, get_db
from .integrations.prowler import normalize
from .overview import build_overview
from .scanner import run_scan, save_scan


@asynccontextmanager
async def lifespan(app):
    Base.metadata.create_all(engine)
    yield


def require_key(x_api_key: str = Header(default="")):
    if config.API_KEY and not secrets.compare_digest(x_api_key, config.API_KEY):
        raise HTTPException(401, "Invalid or missing API key")


app = FastAPI(title="Cloud Security Posture Checker", version="1.0.0", lifespan=lifespan)
api = APIRouter(prefix="/api", dependencies=[Depends(require_key)])


@app.get("/healthz", include_in_schema=False)
def healthz():
    return {"status": "ok"}


def _scan_or_404(db: Session, scan_id: int) -> models.Scan:
    scan = db.get(models.Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return scan


@api.post("/scans", response_model=schemas.ScanOut, status_code=201)
def create_scan(req: schemas.ScanRequest, db: Session = Depends(get_db)):
    try:
        return run_scan(db, req.provider, req.region, req.profile)
    except CollectorError as e:
        raise HTTPException(400, str(e))


@api.get("/scans", response_model=list[schemas.ScanOut])
def list_scans(limit: int = Query(50, ge=1, le=200), db: Session = Depends(get_db)):
    return db.scalars(select(models.Scan).order_by(models.Scan.id.desc()).limit(limit)).all()


@api.get("/scans/{scan_id}", response_model=schemas.ScanOut)
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    return _scan_or_404(db, scan_id)


@api.delete("/scans/{scan_id}", status_code=204)
def delete_scan(scan_id: int, db: Session = Depends(get_db)):
    db.delete(_scan_or_404(db, scan_id))
    db.commit()


@api.get("/scans/{scan_id}/findings", response_model=list[schemas.FindingOut])
def list_findings(scan_id: int, severity: str | None = None, status: str | None = None,
                  service: str | None = None, db: Session = Depends(get_db)):
    _scan_or_404(db, scan_id)
    q = select(models.Finding).where(models.Finding.scan_id == scan_id)
    for col, val in ((models.Finding.severity, severity), (models.Finding.status, status),
                     (models.Finding.service, service)):
        if val:
            q = q.where(col == val)
    return db.scalars(q.order_by(models.Finding.id)).all()


@api.get("/scans/{scan_id}/report")
def report(scan_id: int, format: str = Query("json", pattern="^(json|csv|html)$"),
           db: Session = Depends(get_db)):
    scan = _scan_or_404(db, scan_id)
    fn, media = {"json": (reporting.to_json, "application/json"),
                 "csv": (reporting.to_csv, "text/csv"), "html": (reporting.to_html, "text/html")}[format]
    return Response(fn(scan, scan.findings), media_type=media,
                    headers={"Content-Disposition": f'attachment; filename="posture-scan-{scan.id}.{format}"'})


@api.get("/overview")
def overview(db: Session = Depends(get_db)):
    """Everything the dashboard needs: latest posture per account, standards, queue, insights."""
    return build_overview(db)


@api.get("/trend")
def trend(db: Session = Depends(get_db)):
    rows = db.scalars(select(models.Scan).order_by(models.Scan.id.desc()).limit(30)).all()
    return [{"id": s.id, "score": s.score, "started_at": models.utc(s.started_at), "provider": s.provider}
            for s in reversed(rows)]


@api.post("/integrations/prowler/import", response_model=schemas.ScanOut, status_code=201)
def import_prowler(body: schemas.ProwlerImport, db: Session = Depends(get_db)):
    if len(body.findings) > config.MAX_IMPORT_FINDINGS:
        raise HTTPException(413, "Too many findings in one import")
    findings, account = normalize(body.findings)
    if not findings:
        raise HTTPException(422, "No PASS/FAIL findings recognised (expected Prowler JSON or OCSF)")
    return save_scan(db, provider="aws", source="prowler", account=account, region="", findings=findings)


app.include_router(api)
_front = Path(__file__).resolve().parent.parent / "frontend"
if _front.exists():
    app.mount("/", StaticFiles(directory=_front, html=True), name="frontend")
