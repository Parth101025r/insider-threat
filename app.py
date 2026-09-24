import json

from fastapi import FastAPI, Request, UploadFile, File, HTTPException
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from analysis import getPredictions
from monitor import LOG_FILE, monitor, stop_event, parse_log_file

from typing import Optional
from datetime import datetime, timedelta, date
import threading
import pandas as pd
import numpy as np

app = FastAPI()
monitor_thread: Optional[threading.Thread] = None
monitor_started_at: Optional[str] = None
monitor_lock = threading.Lock()

templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/")
def home(request: Request):
    return templates.TemplateResponse(
        "index.html",
        {"request": request}
    )

@app.post("/api/analysis/logs")
async def logsAnalysis(file: UploadFile = File(...)):
    if not file.filename or not file.filename.lower().endswith(".csv"):
        raise HTTPException(status_code=400, detail="Please upload a CSV file.")

    try:
        data = pd.read_csv(file.file)
        if data.empty:
            raise HTTPException(status_code=400, detail="The uploaded CSV is empty.")

        predictions = getPredictions(data)
        result = data.copy()
        result["prediction"] = predictions
        result["status"] = np.where(
            result["prediction"] == 0,
            "anomaly",
            "normal"
        )

        return {
            "filename": file.filename,
            "total": len(result),
            "anomalies": int((result["prediction"] == 0).sum()),
            "normal": int((result["prediction"] == 1).sum()),
            "results": json.loads(result.to_json(orient="records", date_format="iso"))
        }
    except HTTPException:
        raise
    except Exception as error:
        raise HTTPException(
            status_code=422,
            detail=f"Could not process the CSV: {error}"
        ) from error


@app.post("/api/monitor")
def start_monitoring():
    global monitor_thread, monitor_started_at

    with monitor_lock:
        if monitor_thread and monitor_thread.is_alive():
            return {
                "status": "active",
                "message": "Monitoring is already running.",
                "started_at": monitor_started_at
            }

        stop_event.clear()
        monitor_started_at = datetime.now().isoformat(timespec="seconds")
        monitor_thread = threading.Thread(
            target=monitor,
            name="log-monitor",
            daemon=True
        )
        monitor_thread.start()

        return {
            "status": "active",
            "message": "Monitoring started.",
            "started_at": monitor_started_at
        }


@app.get("/api/monitor")
def monitorResults():
    logs = parse_log_file(LOG_FILE)
    is_active = bool(monitor_thread and monitor_thread.is_alive())
    return {
        "status": "active" if is_active else "inactive",
        "logs": logs
    }
