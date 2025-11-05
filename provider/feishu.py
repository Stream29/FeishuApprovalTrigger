"""Feishu (Lark) approval webhook trigger provider."""

from __future__ import annotations

import json
from typing import Any, Mapping

from werkzeug import Request, Response

from dify_plugin.entities.trigger import EventDispatch, Subscription
from dify_plugin.errors.trigger import TriggerDispatchError, TriggerValidationError
from dify_plugin.interfaces.trigger import Trigger


class FeishuTrigger(Trigger):
    """Handle Feishu approval webhook events with challenge validation and token verification."""

    def _dispatch_event(self, subscription: Subscription, request: Request) -> EventDispatch:
        """
        Dispatch Feishu webhook events.

        Handles:
        1. URL Challenge verification (飞书 challenge 验证)
        2. Event token validation (飞书事件令牌验证)
        3. Event routing to appropriate handlers (事件路由)

        Args:
            subscription: The subscription containing Feishu credentials
            request: The incoming webhook request from Feishu

        Returns:
            EventDispatch containing the response and events to trigger

        Raises:
            TriggerDispatchError: If payload is invalid
            TriggerValidationError: If verification token is invalid
        """
        # 1. Get stored credentials from subscription
        credentials = subscription.properties
        stored_verification_token = credentials.get("verification_token")

        if not stored_verification_token:
            raise TriggerDispatchError("Verification Token is not configured in Dify subscription.")

        # 2. Parse request payload
        try:
            payload = request.get_json(force=True)
            if not isinstance(payload, dict):
                raise TriggerDispatchError("Invalid JSON payload: expected object.")
        except Exception as exc:
            raise TriggerDispatchError(f"Failed to parse JSON payload: {exc}") from exc

        # 3. **核心 Insight 1: 处理飞书 URL Challenge**
        # Feishu sends a challenge request when saving the webhook URL
        # We must immediately return the challenge value
        if payload.get("type") == "url_verification":
            challenge = payload.get("challenge")
            if not challenge:
                raise TriggerDispatchError("Invalid 'url_verification' request: missing 'challenge' field.")

            # Return challenge response immediately
            response = Response(
                response=json.dumps({"challenge": challenge}),
                status=200,
                mimetype="application/json",
            )
            # No Dify events triggered, just HTTP response
            return EventDispatch(response=response, events=[])

        # 4. **核心 Insight 3: 处理飞书事件并验证 Token**
        # For regular events, verify the token in the header
        event_header = payload.get("header", {})
        event_token = event_header.get("token")

        if event_token != stored_verification_token:
            raise TriggerValidationError(
                f"Invalid Verification Token. Expected token from subscription, got: {event_token}"
            )

        # 5. Route to correct event handler based on event_type
        event_type = event_header.get("event_type")

        # We only care about approval instance status updates
        if event_type == "approval.instance.status_updated":
            # Dispatch to 'approval_approved' event handler
            # The handler will filter for APPROVED status
            response = Response(
                response=json.dumps({"message": "ok"}),
                status=200,
                mimetype="application/json",
            )
            # Return the event with its payload for further processing
            return EventDispatch(
                events=[
                    {
                        "event": "approval_approved",  # Must match identity.name in approval_approved.yaml
                        "payload": payload,
                    }
                ],
                response=response,
            )

        # 6. Received an event we subscribed to but don't handle
        # Return 200 OK to Feishu to avoid retries
        response = Response(
            response=json.dumps({"message": "ok"}),
            status=200,
            mimetype="application/json",
        )
        return EventDispatch(response=response, events=[])
