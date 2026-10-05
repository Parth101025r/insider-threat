import json
import math
import tempfile
from pathlib import Path

from fastapi import FastAPI, Request, UploadFile, File, HTTPException
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from analysis import FEATURE_COLUMNS, getPredictions, log_to_csv
from monitor import LOG_FILE, monitor, stop_event, parse_log_file
from collections import Counter
from typing import Any
from pydantic import BaseModel

from typing import Optional
from datetime import datetime, timedelta, date
import threading
import pandas as pd
import numpy as np

app = FastAPI()
monitor_thread: Optional[threading.Thread] = None
monitor_started_at: Optional[str] = None
monitor_lock = threading.Lock()
prediction_batch_size = 50
prediction_buffer: list[dict[str, Any]] = []
prediction_lock = threading.Lock()


class MonitorPredictionRequest(BaseModel):
    rows: list[dict[str, Any]]

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
    if not file.filename:
        raise HTTPException(status_code=400, detail="Please upload a CSV or LOG file.")

    file_extension = Path(file.filename).suffix.lower()
    if file_extension not in {".csv", ".log"}:
        raise HTTPException(status_code=400, detail="Please upload a CSV or LOG file.")

    try:
        if file_extension == ".log":
            with tempfile.TemporaryDirectory() as temp_dir:
                log_path = Path(temp_dir) / "upload.log"
                csv_path = Path(temp_dir) / "converted.csv"
                log_path.write_bytes(await file.read())
                log_to_csv(log_path, csv_path)

                if csv_path.stat().st_size == 0:
                    raise HTTPException(
                        status_code=400,
                        detail="The uploaded log is empty.",
                    )

                data = pd.read_csv(
                    csv_path,
                    header=None,
                    names=["log_line"],
                )
        else:
            data = pd.read_csv(file.file)

        if data.empty:
            raise HTTPException(status_code=400, detail="The uploaded file is empty.")

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


@app.post("/api/monitor/stop")
def stop_monitoring():
    with monitor_lock:
        if not monitor_thread or not monitor_thread.is_alive():
            return {
                "status": "inactive",
                "message": "Monitoring is not running."
            }

        stop_event.set()
        monitor_thread.join(timeout=5)
        is_stopping = monitor_thread.is_alive()
        return {
            "status": "stopping" if is_stopping else "inactive",
            "message": "Stop requested." if is_stopping else "Monitoring stopped."
        }


@app.get("/api/monitor")
def monitorResults():
    logs = parse_log_file(LOG_FILE)
    is_active = bool(monitor_thread and monitor_thread.is_alive())
    return {
        "status": "active" if is_active else "inactive",
        "logs": logs
    }


@app.post("/api/monitor/predictions")
def predict_monitor_rows(payload: MonitorPredictionRequest):
    if not payload.rows:
        raise HTTPException(status_code=422, detail="At least one row is required.")

    incoming_rows = []
    for row_index, row in enumerate(payload.rows):
        missing_columns = [column for column in FEATURE_COLUMNS if column not in row]
        if missing_columns:
            raise HTTPException(
                status_code=422,
                detail=f"Row {row_index} is missing model features: {', '.join(missing_columns)}",
            )

        try:
            features = {column: float(row[column]) for column in FEATURE_COLUMNS}
        except (TypeError, ValueError):
            raise HTTPException(
                status_code=422,
                detail=f"Row {row_index} contains a non-numeric model feature.",
            ) from None

        if not all(math.isfinite(value) for value in features.values()):
            raise HTTPException(
                status_code=422,
                detail=f"Row {row_index} contains a non-finite model feature.",
            )

        incoming_rows.append({
            "record_id": row.get("record_id"),
            "features": features,
        })

    with prediction_lock:
        prediction_buffer.extend(incoming_rows)
        completed_row_count = len(prediction_buffer) // prediction_batch_size * prediction_batch_size
        completed_batches = []

        if completed_row_count:
            ready_rows = prediction_buffer[:completed_row_count]
            feature_frame = pd.DataFrame(
                [row["features"] for row in ready_rows],
                columns=FEATURE_COLUMNS,
            )
            try:
                predictions = getPredictions(feature_frame)
            except Exception as error:
                raise HTTPException(
                    status_code=503,
                    detail=f"Model inference failed; rows remain buffered: {error}",
                ) from error

            for offset in range(0, completed_row_count, prediction_batch_size):
                batch_rows = ready_rows[offset:offset + prediction_batch_size]
                batch_predictions = predictions[offset:offset + prediction_batch_size]
                results = [
                    {
                        "record_id": row["record_id"],
                        "prediction": int(prediction),
                        "status": "anomaly" if prediction == 0 else "normal",
                    }
                    for row, prediction in zip(batch_rows, batch_predictions)
                ]
                completed_batches.append({
                    "results": results,
                    "anomalies": sum(result["prediction"] == 0 for result in results),
                    "normal": sum(result["prediction"] == 1 for result in results),
                })

            del prediction_buffer[:completed_row_count]

        return {
            "batch_size": prediction_batch_size,
            "received": len(incoming_rows),
            "processed_rows": completed_row_count,
            "pending_rows": len(prediction_buffer),
            "batches": completed_batches,
        }


@app.get('/api/dashboard/summary')
def dashboard(start_date: Optional[date] = None, end_date: Optional[date] = None):
    if start_date and end_date and start_date > end_date:
        raise HTTPException(
            status_code=400,
            detail="start_date must be on or before end_date.",
        )

    logs = parse_log_file(LOG_FILE)
    event_counts = Counter()
    daily_counts = Counter()
    filtered_logs = []
    for log in logs:
        try:
            timestamp = datetime.strptime(
                log["timestamp"], "%Y-%m-%d %H:%M:%S"
            )
        except (KeyError, TypeError, ValueError):
            continue

        event_day = timestamp.date()
        if (start_date and event_day < start_date) or (end_date and event_day > end_date):
            continue

        filtered_logs.append(log)
        event_counts[log.get("event", "UNKNOWN")] += 1
        daily_counts[event_day.isoformat()] += 1

    recent_logs = sorted(
        filtered_logs,
        key=lambda log: log["timestamp"],
        reverse=True,
    )

    return {
        "total_events": len(filtered_logs),
        "events_by_type": dict(event_counts),
        "time_series": [
            {"date": day, "events": count}
            for day, count in sorted(daily_counts.items())
        ],
        "latest_event": recent_logs[0] if recent_logs else None,
        "recent_events": recent_logs[:8],
    }
