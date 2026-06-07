from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_current_user, require_admin
from app.models.lab_test import LabTest
from app.models.user import User
from app.schemas.lab_test import LabTestCreate, LabTestOut, LabTestUpdate

router = APIRouter()


@router.get("", response_model=list[LabTestOut])
def list_lab_tests(
    category: str | None = None,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    q = db.query(LabTest).filter(LabTest.is_active)
    if category:
        q = q.filter(LabTest.category == category)
    return q.all()


@router.get("/{test_id}", response_model=LabTestOut)
def get_lab_test(
    test_id: UUID,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    test = db.query(LabTest).filter(LabTest.id == test_id).first()
    if not test:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Lab test not found"
        )
    return test


@router.post("", response_model=LabTestOut, status_code=status.HTTP_201_CREATED)
def create_lab_test(
    payload: LabTestCreate,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    test = LabTest(**payload.model_dump())
    db.add(test)
    db.commit()
    db.refresh(test)
    return test


@router.put("/{test_id}", response_model=LabTestOut)
def update_lab_test(
    test_id: UUID,
    payload: LabTestUpdate,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    test = db.query(LabTest).filter(LabTest.id == test_id).first()
    if not test:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Lab test not found"
        )
    for field, value in payload.model_dump(exclude_none=True).items():
        setattr(test, field, value)
    db.commit()
    db.refresh(test)
    return test


@router.delete("/{test_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_lab_test(
    test_id: UUID,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    test = db.query(LabTest).filter(LabTest.id == test_id).first()
    if not test:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Lab test not found"
        )
    # Soft-delete
    test.is_active = False
    db.commit()
