"""Feishu approval approved event handler."""

from __future__ import annotations

from typing import Any, Mapping

from werkzeug import Request

from dify_plugin.entities.trigger import Variables
from dify_plugin.errors.trigger import EventIgnoreError
from dify_plugin.interfaces.trigger import Event


class FeishuApprovalApprovedEvent(Event):
    """
    Feishu approval approved event handler.

    Filters and processes only APPROVED status events from Feishu approval system.
    """

    def _on_event(self, request: Request, parameters: Mapping[str, Any], payload: Mapping[str, Any]) -> Variables:
        """
        Process Feishu approval event and filter for APPROVED status.

        This is the core Insight 4 implementation:
        - Filter out non-APPROVED events (PENDING, REJECTED, etc.)
        - Extract and transform data for Dify workflow
        - Use EventIgnoreError to silently drop unwanted events

        Args:
            request: The original HTTP request (not used here)
            parameters: Event parameters from YAML (empty for this event)
            payload: The complete Feishu event payload from _dispatch_event

        Returns:
            Variables containing the approval data to inject into Dify workflow

        Raises:
            EventIgnoreError: If the event status is not APPROVED
        """
        # 1. **核心 Insight 4: 过滤非 "APPROVED" 事件**
        # Extract event data from Feishu V2 schema
        event_data = payload.get("event", {})
        event_object = event_data.get("object", {})
        status = event_object.get("status")

        # Filter: only process APPROVED status
        if status != "APPROVED":
            # Silently drop the event - no workflow trigger
            raise EventIgnoreError(f"Ignoring non-APPROVED status: {status}")

        # 2. Extract data to match output_schema in approval_approved.yaml
        instance_code = event_object.get("instance_code")
        approval_code = event_object.get("approval_code")
        operate_time = event_object.get("operate_time")  # Feishu v4 uses int64 timestamp
        uuid = event_object.get("uuid")

        # Extract from header
        event_header = payload.get("header", {})
        app_id = event_header.get("app_id")
        event_id = event_header.get("event_id")

        # 3. Validate required fields
        if not instance_code or not approval_code:
            raise EventIgnoreError("Event is missing required 'instance_code' or 'approval_code'.")

        # 4. Return variables to inject into Dify workflow
        # These must match the output_schema defined in approval_approved.yaml
        return Variables(
            variables={
                "instance_code": instance_code,
                "approval_code": approval_code,
                "status": status,  # Always "APPROVED" at this point
                "operate_time": str(operate_time) if operate_time else "",  # Convert to string for Dify
                "app_id": app_id or "",
                "event_id": event_id or "",  # For idempotency checking
                "uuid": uuid or "",
            }
        )
