"""
models/model_manager.py — SQLite alert database + model training.

Why this exists:
  All intrusion alerts must be persisted so the dashboard can show 
  historical data and statistics. SQLite is used because it requires 
  zero configuration and is ideal for a proof-of-concept.

  The training logic lives here (alongside DB access) because training 
  is a model-lifecycle concern separate from detection serving.

How it connects to the NIDS architecture:
  - detection_service.py calls get_alert_db().insert_alert() after every 
    intrusion is detected.
  - /api/alerts and /api/statistics routes call get_alert_db() to query 
    stored alerts.
  - /api/train calls train_model() which reads sample_data.csv, fits 
    an Isolation Forest, and saves the .joblib file.
"""

import os
import time
import sqlite3
import threading
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import joblib

from backend.config import (
    DATABASE_PATH,
    MODEL_PATH,
    DATASET_PATH,
    FEATURE_COLUMNS,
    ISOLATION_FOREST_CONTAMINATION,
    ISOLATION_FOREST_N_ESTIMATORS,
    ISOLATION_FOREST_RANDOM_STATE,
)
from backend.utils.logger import get_logger

logger = get_logger("model_manager")

# ── Ensure directories exist ──────────────────────────────────────────────────
os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)
os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)


# ══════════════════════════════════════════════════════════════════════════════
# Alert Database
# ══════════════════════════════════════════════════════════════════════════════

class AlertDB:
    """
    Thread-safe SQLite wrapper for storing and querying NIDS alerts.
    """

    # Shared sqlite connection per thread (sqlite3 is thread-hostile)
    _local = threading.local()

    def __init__(self, db_path: str = DATABASE_PATH) -> None:
        self.db_path = db_path
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        """Return a thread-local connection, creating it if needed."""
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(
                self.db_path, check_same_thread=False
            )
            self._local.conn.row_factory = sqlite3.Row
        return self._local.conn

    def _init_db(self) -> None:
        """Create the alerts table if it doesn't exist."""
        conn = self._get_conn()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp       TEXT    NOT NULL,
                duration        REAL    NOT NULL,
                src_bytes       REAL    NOT NULL,
                dst_bytes       REAL    NOT NULL,
                status          TEXT    NOT NULL,
                attack_type     TEXT,
                detection_method TEXT   NOT NULL,
                severity        TEXT,
                anomaly_score   REAL,
                latency_ms      REAL,
                message         TEXT,
                triage_status   TEXT    DEFAULT 'OPEN'
            )
        """)
        # Ensure triage_status column exists in legacy databases
        try:
            conn.execute("ALTER TABLE alerts ADD COLUMN triage_status TEXT DEFAULT 'OPEN'")
        except Exception:
            pass  # Column already exists

        conn.execute("""
            CREATE TABLE IF NOT EXISTS flows (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp       TEXT    NOT NULL,
                duration        REAL    NOT NULL,
                src_bytes       REAL    NOT NULL,
                dst_bytes       REAL    NOT NULL,
                status          TEXT    NOT NULL,
                detection_method TEXT   NOT NULL,
                latency_ms      REAL
            )
        """)
        conn.commit()
        logger.info("Alert database initialised at %s", self.db_path)

    def update_triage_status(self, alert_id: int, triage_status: str) -> bool:
        """Update triage status for an alert (OPEN, ACKNOWLEDGED, RESOLVED, FALSE_POSITIVE)."""
        conn = self._get_conn()
        cursor = conn.execute("""
            UPDATE alerts SET triage_status = ? WHERE id = ?
        """, (triage_status, alert_id))
        conn.commit()
        return cursor.rowcount > 0


    def insert_alert(self, result: Dict[str, Any]) -> None:
        """Persist an intrusion detection result."""
        conn = self._get_conn()
        conn.execute("""
            INSERT INTO alerts
              (timestamp, duration, src_bytes, dst_bytes, status,
               attack_type, detection_method, severity, anomaly_score,
               latency_ms, message)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            result.get("timestamp", datetime.now(timezone.utc).isoformat()),
            result.get("duration", 0),
            result.get("src_bytes", 0),
            result.get("dst_bytes", 0),
            result.get("status", "UNKNOWN"),
            result.get("attack_type"),
            result.get("detection_method", "UNKNOWN"),
            result.get("severity"),
            result.get("anomaly_score"),
            result.get("latency_ms"),
            result.get("message"),
        ))
        conn.commit()

    def log_flow(self, result: Dict[str, Any]) -> None:
        """Log every flow (normal + intrusion) for statistics."""
        conn = self._get_conn()
        conn.execute("""
            INSERT INTO flows
              (timestamp, duration, src_bytes, dst_bytes, status,
               detection_method, latency_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            result.get("timestamp", datetime.now(timezone.utc).isoformat()),
            result.get("duration", 0),
            result.get("src_bytes", 0),
            result.get("dst_bytes", 0),
            result.get("status", "UNKNOWN"),
            result.get("detection_method", "UNKNOWN"),
            result.get("latency_ms"),
        ))
        conn.commit()

    def get_alerts(self, limit: int = 100) -> List[Dict]:
        """Return the most recent *limit* intrusion alerts."""
        conn = self._get_conn()
        cursor = conn.execute("""
            SELECT * FROM alerts ORDER BY id DESC LIMIT ?
        """, (limit,))
        return [dict(row) for row in cursor.fetchall()]

    def get_statistics(self) -> Dict[str, Any]:
        """Compute detection statistics from stored flow data."""
        conn = self._get_conn()

        total_flows = conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0]
        normal_flows = conn.execute(
            "SELECT COUNT(*) FROM flows WHERE status='NORMAL'"
        ).fetchone()[0]
        intrusion_flows = conn.execute(
            "SELECT COUNT(*) FROM flows WHERE status='INTRUSION'"
        ).fetchone()[0]
        rule_detections = conn.execute(
            "SELECT COUNT(*) FROM flows WHERE detection_method='RULE'"
        ).fetchone()[0]
        ml_detections = conn.execute(
            "SELECT COUNT(*) FROM flows WHERE detection_method='ISOLATION_FOREST'"
        ).fetchone()[0]

        avg_latency = conn.execute(
            "SELECT AVG(latency_ms) FROM flows WHERE latency_ms IS NOT NULL"
        ).fetchone()[0] or 0.0

        # Attack type distribution (from alerts table)
        rows = conn.execute("""
            SELECT attack_type, COUNT(*) as cnt
            FROM alerts
            WHERE attack_type IS NOT NULL
            GROUP BY attack_type
        """).fetchall()
        attack_distribution = {row["attack_type"]: row["cnt"] for row in rows}

        detection_pct = (
            round(intrusion_flows / total_flows * 100, 2)
            if total_flows > 0 else 0.0
        )

        return {
            "total_flows":       total_flows,
            "normal_flows":      normal_flows,
            "intrusion_flows":   intrusion_flows,
            "rule_detections":   rule_detections,
            "ml_detections":     ml_detections,
            "detection_percentage": detection_pct,
            "avg_latency_ms":    round(avg_latency, 3),
            "attack_distribution": attack_distribution,
        }


# ── Module-level singleton ────────────────────────────────────────────────────
_alert_db: Optional[AlertDB] = None


def get_alert_db() -> AlertDB:
    global _alert_db
    if _alert_db is None:
        _alert_db = AlertDB()
    return _alert_db


# ══════════════════════════════════════════════════════════════════════════════
# Model Training
# ══════════════════════════════════════════════════════════════════════════════

def train_model() -> Dict[str, Any]:
    """
    Load sample_data.csv, train an Isolation Forest on normal traffic 
    features, and save the model to models/isoforest_model.joblib.

    IMPORTANT: Labels are NOT passed to IsolationForest — this is 
    unsupervised learning. The 'label' column (if present) is used only 
    to filter training to NORMAL flows, mimicking a real deployment where 
    you would train on a clean baseline capture.

    Returns:
        Dictionary with training metadata.
    """
    if not os.path.exists(DATASET_PATH):
        raise FileNotFoundError(
            f"Training dataset not found at {DATASET_PATH}. "
            "Run: python scripts/generate_dataset.py"
        )

    logger.info("Loading training data from %s", DATASET_PATH)
    df = pd.read_csv(DATASET_PATH)

    # Validate required columns
    missing = [c for c in FEATURE_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"Dataset missing columns: {missing}")

    # Train only on NORMAL rows if label column is present
    if "label" in df.columns:
        train_df = df[df["label"] == "NORMAL"][FEATURE_COLUMNS].dropna()
        logger.info(
            "Training on NORMAL-labelled rows only (%d / %d total).",
            len(train_df), len(df),
        )
    else:
        train_df = df[FEATURE_COLUMNS].dropna()
        logger.info("No 'label' column found; training on all %d rows.", len(train_df))

    X = train_df.values

    # Fit Isolation Forest
    logger.info(
        "Fitting IsolationForest (n_estimators=%d, contamination=%s, seed=%d) ...",
        ISOLATION_FOREST_N_ESTIMATORS,
        ISOLATION_FOREST_CONTAMINATION,
        ISOLATION_FOREST_RANDOM_STATE,
    )
    t0 = time.monotonic()
    model = IsolationForest(
        n_estimators=ISOLATION_FOREST_N_ESTIMATORS,
        contamination=ISOLATION_FOREST_CONTAMINATION,
        random_state=ISOLATION_FOREST_RANDOM_STATE,
        n_jobs=-1,
    )
    model.fit(X)
    elapsed = time.monotonic() - t0

    # Persist model
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    logger.info("Model saved to %s (training took %.2f s)", MODEL_PATH, elapsed)

    return {
        "status":           "success",
        "samples_trained":  int(len(X)),
        "features":         FEATURE_COLUMNS,
        "contamination":    ISOLATION_FOREST_CONTAMINATION,
        "n_estimators":     ISOLATION_FOREST_N_ESTIMATORS,
        "random_state":     ISOLATION_FOREST_RANDOM_STATE,
        "model_path":       MODEL_PATH,
        "training_time_s":  round(elapsed, 3),
        "timestamp":        datetime.now(timezone.utc).isoformat(),
    }
