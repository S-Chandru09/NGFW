import math
import re
from typing import Any

from pymongo import ASCENDING, DESCENDING

from database import get_users_collection
from models.user import UserDocument, UserPublic, UserRole
from schemas.log import PaginationMeta
from schemas.user import UserFilterParams, UserListResponse


class UserService:
  def _build_pagination_meta(self, page: int, page_size: int, total_items: int) -> PaginationMeta:
    total_pages = math.ceil(total_items / page_size) if page_size > 0 else 0

    return PaginationMeta(
      page=page,
      page_size=page_size,
      total_items=total_items,
      total_pages=total_pages,
      has_next=page < total_pages,
      has_previous=page > 1 and total_pages > 0,
    )

  def _get_sort_direction(self, sort_order: str) -> int:
    return ASCENDING if sort_order.lower() == "asc" else DESCENDING

  def _build_filter_query(self, filters: UserFilterParams) -> dict[str, Any]:
    query: dict[str, Any] = {}

    if filters.role is not None:
      query["role"] = filters.role.value

    if filters.is_active is not None:
      query["is_active"] = filters.is_active

    if filters.search:
      escaped = re.escape(filters.search.strip())
      query["$or"] = [
        {"email": {"$regex": escaped, "$options": "i"}},
        {"username": {"$regex": escaped, "$options": "i"}},
        {"full_name": {"$regex": escaped, "$options": "i"}},
      ]

    return query

  async def list_users(
    self,
    page: int = 1,
    page_size: int = 20,
    filters: UserFilterParams | None = None,
    sort_by: str = "created_at",
    sort_order: str = "desc",
  ) -> UserListResponse:
    users_collection = get_users_collection()
    filter_query = self._build_filter_query(filters or UserFilterParams())
    sort_field = sort_by if sort_by in {"created_at", "updated_at", "email", "username", "role"} else "created_at"
    sort_direction = self._get_sort_direction(sort_order)
    skip = (page - 1) * page_size

    total_items = await users_collection.count_documents(filter_query)
    cursor = (
      users_collection.find(filter_query)
      .sort(sort_field, sort_direction)
      .skip(skip)
      .limit(page_size)
    )

    documents = await cursor.to_list(length=page_size)
    items = [
      public_user
      for document in documents
      if (public_user := UserDocument.to_public_from_mongo(document)) is not None
    ]

    return UserListResponse(
      message="Users retrieved successfully",
      items=items,
      pagination=self._build_pagination_meta(page, page_size, total_items),
    )


user_service = UserService()
