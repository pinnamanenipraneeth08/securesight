"""
SecureSight - Detection Rule Management Endpoints
"""

from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import structlog

from app.core.database import get_db
from app.core.security import get_current_user, require_roles, TokenData
from app.models.rule import Rule, RuleType, RuleSeverity

logger = structlog.get_logger()
router = APIRouter()


class RuleCreate(BaseModel):
    name: str
    description: Optional[str] = None
    rule_type: RuleType = RuleType.THRESHOLD
    severity: RuleSeverity = RuleSeverity.MEDIUM
    logic: dict
    actions: Optional[List[str]] = []
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    tags: Optional[List[str]] = []


class RuleResponse(BaseModel):
    id: str
    name: str
    description: Optional[str]
    rule_type: str
    severity: str
    logic: dict
    is_enabled: bool
    is_test_mode: bool
    actions: Optional[List[str]]
    hit_count: int
    created_at: datetime
    
    class Config:
        from_attributes = True


class RuleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[RuleSeverity] = None
    logic: Optional[dict] = None
    is_enabled: Optional[bool] = None
    is_test_mode: Optional[bool] = None
    actions: Optional[List[str]] = None


@router.get("/", response_model=List[RuleResponse])
async def list_rules(
    rule_type: Optional[RuleType] = None,
    enabled_only: bool = False,
    skip: int = 0,
    limit: int = 100,
    current_user: TokenData = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List detection rules"""
    query = select(Rule)
    
    if rule_type:
        query = query.where(Rule.rule_type == rule_type)
    if enabled_only:
        query = query.where(Rule.is_enabled == True)
    
    query = query.order_by(Rule.created_at.desc()).offset(skip).limit(limit)
    
    result = await db.execute(query)
    rules = result.scalars().all()
    
    return [
        RuleResponse(
            id=str(r.id),
            name=r.name,
            description=r.description,
            rule_type=r.rule_type.value,
            severity=r.severity.value,
            logic=r.logic,
            is_enabled=r.is_enabled,
            is_test_mode=r.is_test_mode,
            actions=r.actions,
            hit_count=r.hit_count,
            created_at=r.created_at,
        )
        for r in rules
    ]


@router.post("/", response_model=RuleResponse)
async def create_rule(
    rule_data: RuleCreate,
    current_user: TokenData = Depends(require_roles(["admin", "analyst"])),
    db: AsyncSession = Depends(get_db),
):
    """Create a new detection rule"""
    rule = Rule(
        name=rule_data.name,
        description=rule_data.description,
        rule_type=rule_data.rule_type,
        severity=rule_data.severity,
        logic=rule_data.logic,
        actions=rule_data.actions,
        mitre_tactic=rule_data.mitre_tactic,
        mitre_technique=rule_data.mitre_technique,
        tags=rule_data.tags,
        author=current_user.sub,
    )
    
    db.add(rule)
    await db.flush()
    
    logger.info("Rule created", rule_id=str(rule.id), name=rule.name)
    
    return RuleResponse(
        id=str(rule.id),
        name=rule.name,
        description=rule.description,
        rule_type=rule.rule_type.value,
        severity=rule.severity.value,
        logic=rule.logic,
        is_enabled=rule.is_enabled,
        is_test_mode=rule.is_test_mode,
        actions=rule.actions,
        hit_count=rule.hit_count,
        created_at=rule.created_at,
    )


@router.get("/{rule_id}", response_model=RuleResponse)
async def get_rule(
    rule_id: str,
    current_user: TokenData = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get rule by ID"""
    result = await db.execute(select(Rule).where(Rule.id == rule_id))
    rule = result.scalar_one_or_none()
    
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rule not found"
        )
    
    return RuleResponse(
        id=str(rule.id),
        name=rule.name,
        description=rule.description,
        rule_type=rule.rule_type.value,
        severity=rule.severity.value,
        logic=rule.logic,
        is_enabled=rule.is_enabled,
        is_test_mode=rule.is_test_mode,
        actions=rule.actions,
        hit_count=rule.hit_count,
        created_at=rule.created_at,
    )


@router.patch("/{rule_id}", response_model=RuleResponse)
async def update_rule(
    rule_id: str,
    update: RuleUpdate,
    current_user: TokenData = Depends(require_roles(["admin", "analyst"])),
    db: AsyncSession = Depends(get_db),
):
    """Update a detection rule"""
    result = await db.execute(select(Rule).where(Rule.id == rule_id))
    rule = result.scalar_one_or_none()
    
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rule not found"
        )
    
    if update.name is not None:
        rule.name = update.name
    if update.description is not None:
        rule.description = update.description
    if update.severity is not None:
        rule.severity = update.severity
    if update.logic is not None:
        rule.logic = update.logic
    if update.is_enabled is not None:
        rule.is_enabled = update.is_enabled
    if update.is_test_mode is not None:
        rule.is_test_mode = update.is_test_mode
    if update.actions is not None:
        rule.actions = update.actions
    
    await db.flush()
    
    logger.info("Rule updated", rule_id=rule_id, by=current_user.sub)
    
    return RuleResponse(
        id=str(rule.id),
        name=rule.name,
        description=rule.description,
        rule_type=rule.rule_type.value,
        severity=rule.severity.value,
        logic=rule.logic,
        is_enabled=rule.is_enabled,
        is_test_mode=rule.is_test_mode,
        actions=rule.actions,
        hit_count=rule.hit_count,
        created_at=rule.created_at,
    )


@router.delete("/{rule_id}")
async def delete_rule(
    rule_id: str,
    current_user: TokenData = Depends(require_roles(["admin"])),
    db: AsyncSession = Depends(get_db),
):
    """Delete a detection rule"""
    result = await db.execute(select(Rule).where(Rule.id == rule_id))
    rule = result.scalar_one_or_none()
    
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rule not found"
        )
    
    await db.delete(rule)
    
    logger.info("Rule deleted", rule_id=rule_id, by=current_user.sub)
    
    return {"status": "deleted", "rule_id": rule_id}


@router.post("/{rule_id}/toggle")
async def toggle_rule(
    rule_id: str,
    current_user: TokenData = Depends(require_roles(["admin", "analyst"])),
    db: AsyncSession = Depends(get_db),
):
    """Toggle rule enabled/disabled"""
    result = await db.execute(select(Rule).where(Rule.id == rule_id))
    rule = result.scalar_one_or_none()
    
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rule not found"
        )
    
    rule.is_enabled = not rule.is_enabled
    await db.flush()
    
    return {"rule_id": rule_id, "is_enabled": rule.is_enabled}


@router.post("/{rule_id}/test")
async def test_rule(
    rule_id: str,
    test_data: dict,
    current_user: TokenData = Depends(require_roles(["admin", "analyst"])),
    db: AsyncSession = Depends(get_db),
):
    """Test a rule against sample log data"""
    result = await db.execute(select(Rule).where(Rule.id == rule_id))
    rule = result.scalar_one_or_none()
    
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rule not found"
        )
    
    # Import detection engine for testing
    from app.services.detection_engine import evaluate_rule
    
    try:
        matches = await evaluate_rule(rule.to_dict(), [test_data])
        return {
            "rule_id": rule_id,
            "matched": len(matches) > 0,
            "matches": matches,
        }
    except Exception as e:
        return {
            "rule_id": rule_id,
            "error": str(e),
            "matched": False,
        }
