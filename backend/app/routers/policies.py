import os
import json
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import get_db
from app import models

router = APIRouter()

POLICIES_DIR = os.path.join(os.path.dirname(__file__), "..", "policies")

def load_policies():
    policies = []
    if os.path.exists(POLICIES_DIR):
        for filename in os.listdir(POLICIES_DIR):
            if filename.endswith(".json"):
                with open(os.path.join(POLICIES_DIR, filename), "r") as f:
                    policies.append(json.load(f))
    return policies

@router.get("/")
def get_policies():
    return load_policies()
