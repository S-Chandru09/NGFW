from typing import Optional

from fastapi import APIRouter, Depends, Query

from core.auth_utils import require_permission
from models.firewall_rule import FirewallProtocol, FirewallRuleAction, FirewallRuleCreate
from models.user import UserPublic
from schemas.firewall_rule import (
  AllowRuleCreate,
  BlacklistRuleCreate,
  BlockRuleCreate,
  FirewallRuleCreateResponse,
  FirewallRuleDeleteResponse,
  FirewallRuleDetailResponse,
  FirewallRuleFilterParams,
  FirewallRuleListResponse,
  FirewallRuleStatsResponse,
  FirewallRuleUpdate,
  FirewallRuleUpdateResponse,
  TemporaryBlockRuleCreate,
  WhitelistRuleCreate,
)
from services.firewall_rule_service import firewall_rule_service

router = APIRouter(prefix="/firewall-rules", tags=["Firewall Rules"])


@router.post(
  "",
  response_model=FirewallRuleCreateResponse,
  status_code=201,
  summary="Create a firewall rule",
)
async def create_firewall_rule(
  rule_data: FirewallRuleCreate,
  current_user: UserPublic = Depends(require_permission("firewall:write")),
) -> FirewallRuleCreateResponse:
  return await firewall_rule_service.create_rule(
    rule_data=rule_data,
    created_by=str(current_user.id),
  )


@router.post(
  "/allow",
  response_model=FirewallRuleCreateResponse,
  status_code=201,
  summary="Create an allow firewall rule",
)
async def create_allow_rule(
  rule_data: AllowRuleCreate,
  current_user: UserPublic = Depends(require_permission("firewall:write")),
) -> FirewallRuleCreateResponse:
  return await firewall_rule_service.create_rule(
    rule_data=rule_data,
    created_by=str(current_user.id),
  )


@router.post(
  "/block",
  response_model=FirewallRuleCreateResponse,
  status_code=201,
  summary="Create a block firewall rule",
)
async def create_block_rule(
  rule_data: BlockRuleCreate,
  current_user: UserPublic = Depends(require_permission("firewall:write")),
) -> FirewallRuleCreateResponse:
  return await firewall_rule_service.create_rule(
    rule_data=rule_data,
    created_by=str(current_user.id),
  )


@router.post(
  "/whitelist",
  response_model=FirewallRuleCreateResponse,
  status_code=201,
  summary="Create a whitelist firewall rule",
)
async def create_whitelist_rule(
  rule_data: WhitelistRuleCreate,
  current_user: UserPublic = Depends(require_permission("firewall:write")),
) -> FirewallRuleCreateResponse:
  return await firewall_rule_service.create_rule(
    rule_data=rule_data,
    created_by=str(current_user.id),
  )


@router.post(
  "/blacklist",
  response_model=FirewallRuleCreateResponse,
  status_code=201,
  summary="Create a blacklist firewall rule",
)
async def create_blacklist_rule(
  rule_data: BlacklistRuleCreate,
  current_user: UserPublic = Depends(require_permission("firewall:write")),
) -> FirewallRuleCreateResponse:
  return await firewall_rule_service.create_rule(
    rule_data=rule_data,
    created_by=str(current_user.id),
  )


@router.post(
  "/temporary-block",
  response_model=FirewallRuleCreateResponse,
  status_code=201,
  summary="Create a temporary block firewall rule",
)
async def create_temporary_block_rule(
  rule_data: TemporaryBlockRuleCreate,
  current_user: UserPublic = Depends(require_permission("firewall:write")),
) -> FirewallRuleCreateResponse:
  return await firewall_rule_service.create_rule(
    rule_data=rule_data.to_firewall_rule_create(),
    created_by=str(current_user.id),
  )


@router.get(
  "",
  response_model=FirewallRuleListResponse,
  summary="List firewall rules with pagination and filtering",
)
async def list_firewall_rules(
  page: int = Query(default=1, ge=1),
  page_size: int = Query(default=20, ge=1, le=100),
  action: Optional[FirewallRuleAction] = Query(default=None),
  protocol: Optional[FirewallProtocol] = Query(default=None),
  source_ip: Optional[str] = Query(default=None),
  destination_ip: Optional[str] = Query(default=None),
  is_enabled: Optional[bool] = Query(default=None),
  is_expired: Optional[bool] = Query(default=None),
  created_by: Optional[str] = Query(default=None),
  sort_by: str = Query(default="priority"),
  sort_order: str = Query(default="desc", pattern="^(asc|desc)$"),
  current_user: UserPublic = Depends(require_permission("firewall:read")),
) -> FirewallRuleListResponse:
  filters = FirewallRuleFilterParams(
    action=action,
    protocol=protocol,
    source_ip=source_ip,
    destination_ip=destination_ip,
    is_enabled=is_enabled,
    is_expired=is_expired,
    created_by=created_by,
  )

  return await firewall_rule_service.list_rules(
    page=page,
    page_size=page_size,
    filters=filters,
    sort_by=sort_by,
    sort_order=sort_order,
  )


@router.get(
  "/stats",
  response_model=FirewallRuleStatsResponse,
  summary="Get firewall rule statistics by action type",
)
async def get_firewall_rule_stats(
  current_user: UserPublic = Depends(require_permission("firewall:read")),
) -> FirewallRuleStatsResponse:
  return await firewall_rule_service.get_stats()


@router.get(
  "/{rule_id}",
  response_model=FirewallRuleDetailResponse,
  summary="Get a firewall rule by ID",
)
async def get_firewall_rule(
  rule_id: str,
  current_user: UserPublic = Depends(require_permission("firewall:read")),
) -> FirewallRuleDetailResponse:
  return await firewall_rule_service.get_rule(rule_id)


@router.put(
  "/{rule_id}",
  response_model=FirewallRuleUpdateResponse,
  summary="Update a firewall rule (full update)",
)
async def update_firewall_rule(
  rule_id: str,
  update_data: FirewallRuleUpdate,
  current_user: UserPublic = Depends(require_permission("firewall:write")),
) -> FirewallRuleUpdateResponse:
  return await firewall_rule_service.update_rule(
    rule_id=rule_id,
    update_data=update_data,
    partial=False,
  )


@router.patch(
  "/{rule_id}",
  response_model=FirewallRuleUpdateResponse,
  summary="Partially update a firewall rule",
)
async def patch_firewall_rule(
  rule_id: str,
  update_data: FirewallRuleUpdate,
  current_user: UserPublic = Depends(require_permission("firewall:write")),
) -> FirewallRuleUpdateResponse:
  return await firewall_rule_service.update_rule(
    rule_id=rule_id,
    update_data=update_data,
    partial=True,
  )


@router.delete(
  "/{rule_id}",
  response_model=FirewallRuleDeleteResponse,
  summary="Delete a firewall rule",
)
async def delete_firewall_rule(
  rule_id: str,
  current_user: UserPublic = Depends(require_permission("firewall:delete")),
) -> FirewallRuleDeleteResponse:
  return await firewall_rule_service.delete_rule(rule_id)
