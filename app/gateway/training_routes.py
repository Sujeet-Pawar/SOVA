"""Training Routes - endpoints for retraining the anomaly model from the UI."""

import sys
import json
import time
import numpy as np
from pathlib import Path
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, BackgroundTasks
from fastapi.responses import JSONResponse
from pydantic import BaseModel

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import yaml
from app.request_processing.parser import HTTPRequest
from app.feature_engine.pipeline import FeaturePipeline
from app.detection.anomaly.model import AnomalyModel
from app.detection.anomaly.trainer import AnomalyTrainer
from app.detection.anomaly.evaluator import AnomalyEvaluator
from app.detection.anomaly.detector import AnomalyDetector


def load_config() -> dict:
    config_path = PROJECT_ROOT / "config" / "config.yaml"
    if config_path.exists():
        with open(config_path) as f:
            return yaml.safe_load(f)
    return {}


router = APIRouter(prefix="/api/training", tags=["training"])
config = load_config()

# Training job state
_training_state = {
    "status": "idle",  # idle, running, completed, error
    "progress": 0,
    "message": "",
    "stats": None,
    "eval_results": None,
    "started_at": None,
    "completed_at": None,
}


class TrainRequest(BaseModel):
    contamination: float = 0.1
    n_estimators: int = 100
    random_state: int = 42
    train_split: str = "train"


def _load_jsonl(filepath: str) -> list[dict]:
    records = []
    if not Path(filepath).exists():
        return records
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def _dict_to_request(data: dict) -> HTTPRequest:
    return HTTPRequest(
        request_id=data.get("request_id", "TRAIN"),
        source_id=data.get("source_id", "TRAIN"),
        method=data.get("method", "GET"),
        path=data.get("path", "/"),
        query=data.get("query", {}),
        query_string=data.get("query_string", ""),
        headers=data.get("headers", {}),
        body_fields=data.get("body_fields", []),
        body_size=data.get("body_size", 0),
        session_id=data.get("session_id", "TRAIN"),
        content_type=data.get("content_type", ""),
        user_agent=data.get("headers", {}).get("user-agent", ""),
    )


def _run_training(params: dict):
    """Run the training pipeline in background."""
    global _training_state
    _training_state["status"] = "running"
    _training_state["progress"] = 0
    _training_state["message"] = "Loading training data..."
    _training_state["started_at"] = datetime.utcnow().isoformat()

    try:
        # Step 1: Load data
        train_split = params.get("train_split", "train")
        records = _load_jsonl(f"data/normalized/{train_split}.jsonl")
        if not records:
            _training_state["status"] = "error"
            _training_state["message"] = f"No training data found in data/normalized/{train_split}.jsonl"
            return

        _training_state["progress"] = 10
        _training_state["message"] = f"Loaded {len(records)} records. Extracting features..."

        # Step 2: Extract features
        pipeline = FeaturePipeline()
        requests = [_dict_to_request(r) for r in records]
        feature_matrix = pipeline.extract_batch(requests)
        labels = [r.get("label", "UNKNOWN") for r in records]

        _training_state["progress"] = 30
        _training_state["message"] = f"Extracted {feature_matrix.shape[1]} features from {len(requests)} samples."

        # Step 3: Separate normal traffic for training
        normal_indices = [i for i, l in enumerate(labels) if l == "NORMAL"]
        if len(normal_indices) < 5:
            _training_state["status"] = "error"
            _training_state["message"] = f"Not enough normal traffic samples ({len(normal_indices)}). Need at least 5."
            return

        normal_features = feature_matrix[normal_indices]
        _training_state["progress"] = 40
        _training_state["message"] = f"Training on {len(normal_indices)} normal samples..."

        # Step 4: Train model
        trainer = AnomalyTrainer(config={
            "contamination": params.get("contamination", 0.1),
            "n_estimators": params.get("n_estimators", 100),
            "random_state": params.get("random_state", 42),
        })

        train_stats = trainer.train_from_features(normal_features)

        _training_state["progress"] = 70
        _training_state["message"] = "Model trained. Saving..."

        # Step 5: Save model
        model_path = "data/models/anomaly_model.joblib"
        trainer.save(model_path)

        _training_state["progress"] = 80
        _training_state["message"] = "Evaluating model on test data..."

        # Step 6: Evaluate
        eval_results = None
        test_features_path = "data/features/test_features.npy"
        test_metadata_path = "data/features/test_metadata.json"

        if Path(test_features_path).exists():
            test_features = np.load(test_features_path)
            with open(test_metadata_path) as f:
                test_meta = json.load(f)
            test_labels = test_meta.get("labels", [])

            attack_indices = [i for i, l in enumerate(test_labels) if l == "ATTACK"]
            normal_test_indices = [i for i, l in enumerate(test_labels) if l == "NORMAL"]

            if attack_indices and normal_test_indices:
                evaluator = AnomalyEvaluator()
                eval_results = evaluator.evaluate(
                    trainer.model,
                    test_features[normal_test_indices],
                    test_features[attack_indices],
                )
                # Convert numpy types to JSON-serializable
                eval_results = {k: float(v) if isinstance(v, (np.floating, float)) else v
                               for k, v in eval_results.items()}

        _training_state["progress"] = 100
        _training_state["status"] = "completed"
        _training_state["message"] = "Training complete!"
        _training_state["stats"] = train_stats
        _training_state["eval_results"] = eval_results
        _training_state["completed_at"] = datetime.utcnow().isoformat()

    except Exception as e:
        _training_state["status"] = "error"
        _training_state["message"] = f"Training failed: {str(e)}"


@router.get("/status")
async def get_training_status():
    """Get current training job status."""
    return _training_state


@router.post("/start")
async def start_training(req: TrainRequest, background_tasks: BackgroundTasks):
    """Start a model training job in the background."""
    if _training_state["status"] == "running":
        return {"error": "Training already in progress"}

    # Reset state
    _training_state.update({
        "status": "queued",
        "progress": 0,
        "message": "Training queued...",
        "stats": None,
        "eval_results": None,
        "started_at": None,
        "completed_at": None,
    })

    background_tasks.add_task(_run_training, req.model_dump())
    return {"status": "queued", "message": "Training job started"}


@router.get("/data-info")
async def get_data_info():
    """Get info about available training data."""
    info = {}

    splits = ["train", "validation", "test"]
    for split in splits:
        path = f"data/normalized/{split}.jsonl"
        records = _load_jsonl(path)
        labels = {}
        for r in records:
            label = r.get("label", "UNKNOWN")
            labels[label] = labels.get(label, 0) + 1
        info[split] = {
            "total": len(records),
            "labels": labels,
            "exists": Path(path).exists(),
        }

    # Check model
    model_path = Path("data/models/anomaly_model.joblib")
    info["model"] = {
        "exists": model_path.exists(),
        "size_kb": round(model_path.stat().st_size / 1024, 1) if model_path.exists() else 0,
        "last_modified": datetime.fromtimestamp(model_path.stat().st_mtime).isoformat() if model_path.exists() else None,
    }

    # Feature info
    features_path = Path("data/features/train_features.npy")
    if features_path.exists():
        features = np.load(features_path)
        info["features"] = {
            "num_samples": features.shape[0],
            "num_features": features.shape[1],
        }

    return info
