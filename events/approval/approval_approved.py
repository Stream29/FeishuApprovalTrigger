"""Feishu approval approved event handler with v1.0 & v2.0 format support."""

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
    Supports both v1.0 and v2.0 event formats.
    """

    def _on_event(self, request: Request, parameters: Mapping[str, Any], payload: Mapping[str, Any]) -> Variables:
        """
        Process Feishu approval event and filter for APPROVED status.

        IMPORTANT: Dify SDK passes an empty payload dict, we must parse from request ourselves!

        Supports:
        - v1.0 format (approval task events): status at payload['event']['status']
        - v2.0 format (instance events): status at payload['event']['object']['status']

        Args:
            request: The original HTTP request - we parse data from this!
            parameters: Event parameters from YAML (empty for this event)
            payload: This is EMPTY from Dify SDK, don't use it

        Returns:
            Variables containing the approval data to inject into Dify workflow

        Raises:
            EventIgnoreError: If the event status is not APPROVED
        """
        # Parse payload from request (Dify SDK doesn't populate the payload parameter)
        try:
            payload = request.get_json(force=True)
        except Exception as exc:
            raise EventIgnoreError(f"Failed to parse request JSON: {exc}") from exc

        # Extract event data
        event_data = payload.get("event", {})

        # Determine format and extract fields accordingly
        # v2.0 format has 'schema' field and nested 'object'
        is_v2 = "schema" in payload and payload.get("schema") == "2.0"

        if is_v2:
            # v2.0 format: approval.instance.status_updated
            event_object = event_data.get("object", {})
            status = event_object.get("status")
            instance_code = event_object.get("instance_code")
            approval_code = event_object.get("approval_code")
            operate_time = event_object.get("operate_time")
            uuid = event_object.get("uuid")

            # Extract from header
            event_header = payload.get("header", {})
            app_id = event_header.get("app_id")
            event_id = event_header.get("event_id")

        else:
            # v1.0 format: approval_task
            status = event_data.get("status")
            instance_code = event_data.get("instance_code")
            approval_code = event_data.get("approval_code")
            operate_time = event_data.get("operate_time")
            uuid = payload.get("uuid")  # v1.0 has uuid at top level

            # v1.0 fields
            app_id = event_data.get("app_id")
            event_id = None  # v1.0 doesn't have event_id, use uuid instead

        # Filter: only process APPROVED status
        if status != "APPROVED":
            raise EventIgnoreError(f"Ignoring non-APPROVED status: {status}")

        # Validate required fields
        if not instance_code or not approval_code:
            raise EventIgnoreError("Event is missing required 'instance_code' or 'approval_code'.")

        # Return variables to inject into Dify workflow
        # These must match the output_schema defined in approval_approved.yaml
        return Variables(
            variables={
                "instance_code": instance_code,
                "approval_code": approval_code,
                "status": status,  # Always "APPROVED" at this point
                "operate_time": str(operate_time) if operate_time else "",
                "app_id": app_id or "",
                "event_id": event_id or uuid or "",  # Use event_id (v2.0) or uuid (v1.0) for idempotency
                "uuid": uuid or "",
            }
        )
