"""Feishu (Lark) approval webhook trigger provider with v1.0 & v2.0 format support."""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any, Mapping

from Crypto.Cipher import AES
from werkzeug import Request, Response

from dify_plugin.entities.trigger import EventDispatch, Subscription
from dify_plugin.errors.trigger import TriggerDispatchError, TriggerValidationError
from dify_plugin.interfaces.trigger import Trigger


class AESCipher:
    """
    AES-256-CBC cipher for Feishu payload decryption.

    Based on Feishu official documentation.
    """

    def __init__(self, key: str) -> None:
        """Initialize AES cipher with Feishu Encrypt Key."""
        self.key = hashlib.sha256(key.encode("utf-8")).digest()
        self.block_size = AES.block_size

    @staticmethod
    def _unpad(data: bytes) -> bytes:
        """Remove PKCS7 padding from decrypted data."""
        return data[: -ord(data[len(data) - 1 :])]

    def decrypt(self, encrypted_str: str) -> str:
        """Decrypt a Base64-encoded encrypted string from Feishu."""
        try:
            encrypted_bytes = base64.b64decode(encrypted_str)
        except Exception as exc:
            raise ValueError(f"Base64 decoding failed: {exc}") from exc

        if len(encrypted_bytes) <= self.block_size:
            raise ValueError("Encrypted data is too short to contain IV.")
        iv = encrypted_bytes[: self.block_size]
        encrypted_data = encrypted_bytes[self.block_size :]

        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        decrypted_bytes = cipher.decrypt(encrypted_data)

        try:
            return self._unpad(decrypted_bytes).decode("utf-8")
        except Exception as exc:
            raise ValueError(f"Unpadding or UTF-8 decoding failed: {exc}") from exc


def verify_signature(
    timestamp: str, nonce: str, encrypt_key: str, body: bytes, signature_header: str
) -> bool:
    """Verify Feishu webhook request signature using SHA256 HMAC."""
    string_to_sign = (timestamp + nonce + encrypt_key).encode("utf-8")
    bytes_to_sign = string_to_sign + body
    calculated_hash = hashlib.sha256(bytes_to_sign)
    calculated_signature = calculated_hash.hexdigest()
    return calculated_signature == signature_header


class FeishuTrigger(Trigger):
    """
    Handle Feishu approval webhook events with v1.0 and v2.0 format support.

    Supports:
    - v1.0 format (approval events): token at payload['token']
    - v2.0 format (general events): token at payload['header']['token']
    - Both plaintext and encrypted modes
    """

    def _dispatch_event(self, subscription: Subscription, request: Request) -> EventDispatch:
        """
        Dispatch Feishu webhook events with flexible format support.

        Process flow:
        1. Extract credentials from subscription
        2. Determine security mode (encrypted vs plaintext)
        3. Verify signature and decrypt payload (if encrypt_key present)
        4. Parse payload (plaintext or decrypted)
        5. Handle URL challenge (webhook registration)
        6. Validate token (support both v1.0 and v2.0 locations)
        7. Route events based on event type

        Args:
            subscription: The subscription containing Feishu credentials
            request: The incoming webhook request from Feishu

        Returns:
            EventDispatch containing the response and events to trigger

        Raises:
            TriggerDispatchError: If payload is invalid or parsing fails
            TriggerValidationError: If signature or token verification fails
        """
        # ===== 1. Extract credentials from subscription =====
        credentials = subscription.properties
        encrypt_key = credentials.get("encrypt_key")
        verification_token = credentials.get("verification_token")

        if not verification_token:
            raise TriggerDispatchError("Verification Token is not configured in subscription.")

        use_encryption = bool(encrypt_key)

        # ===== 2. Security validation based on mode =====
        payload: dict[str, Any]

        if use_encryption:
            # ===== ENCRYPTED MODE: Full security validation =====
            timestamp = request.headers.get("X-Lark-Request-Timestamp")
            nonce = request.headers.get("X-Lark-Request-Nonce")
            signature = request.headers.get("X-Lark-Signature")
            raw_body = request.get_data()

            if timestamp and nonce and signature:
                is_valid = verify_signature(timestamp, nonce, encrypt_key, raw_body, signature)
                if not is_valid:
                    raise TriggerValidationError("Invalid signature.")
            else:
                raise TriggerValidationError("Missing signature headers.")

            try:
                raw_payload = request.get_json(force=True)
                if not isinstance(raw_payload, dict):
                    raise TriggerDispatchError("Invalid JSON payload: expected object.")
            except Exception as exc:
                raise TriggerDispatchError(f"Failed to parse JSON payload: {exc}") from exc

            if "encrypt" in raw_payload:
                cipher = AESCipher(encrypt_key)
                try:
                    decrypted_json_str = cipher.decrypt(raw_payload["encrypt"])
                    payload = json.loads(decrypted_json_str)
                except ValueError as exc:
                    raise TriggerDispatchError(f"Failed to decrypt payload: {exc}") from exc
                except json.JSONDecodeError as exc:
                    raise TriggerDispatchError(f"Decrypted payload is not valid JSON: {exc}") from exc
            else:
                payload = raw_payload

        else:
            # ===== PLAINTEXT MODE: Basic parsing =====
            try:
                payload = request.get_json(force=True)
                if not isinstance(payload, dict):
                    raise TriggerDispatchError("Invalid JSON payload: expected object.")
            except Exception as exc:
                raise TriggerDispatchError(f"Failed to parse JSON payload: {exc}") from exc

        # ===== 3. Handle URL Challenge (webhook registration) =====
        payload_type = payload.get("type")
        if payload_type == "url_verification":
            challenge = payload.get("challenge")
            if not challenge:
                raise TriggerDispatchError("Missing challenge field in url_verification request.")

            response = Response(
                response=json.dumps({"challenge": challenge}),
                status=200,
                mimetype="application/json",
            )
            return EventDispatch(response=response, events=[])

        # ===== 4. Token validation - Support both v1.0 and v2.0 formats =====
        # Try v1.0 location first (approval events), then v2.0 location
        event_token = payload.get("token") or payload.get("header", {}).get("token")

        if not event_token:
            raise TriggerValidationError(
                "Token not found in payload. Checked locations: payload['token'] (v1.0), payload['header']['token'] (v2.0)"
            )

        # Strip whitespace for comparison
        event_token_clean = event_token.strip() if isinstance(event_token, str) else event_token
        verification_token_clean = verification_token.strip()

        if event_token_clean != verification_token_clean:
            raise TriggerValidationError(
                f"Invalid Verification Token. Expected '{verification_token_clean}', got '{event_token_clean}'"
            )

        # ===== 5. Route events based on format and event type =====
        # Check for v2.0 format (has 'schema' and 'header')
        if "schema" in payload and payload.get("schema") == "2.0":
            # v2.0 format
            event_header = payload.get("header", {})
            event_type = event_header.get("event_type")

            if event_type == "approval.instance.status_updated":
                response = Response(
                    response=json.dumps({"message": "ok"}),
                    status=200,
                    mimetype="application/json",
                )
                return EventDispatch(
                    events=["approval_approved"],
                    response=response,
                )

        else:
            # v1.0 format (approval events)
            event_data = payload.get("event", {})
            event_type = event_data.get("type")

            # v1.0 approval task events
            if event_type == "approval_task":
                response = Response(
                    response=json.dumps({"message": "ok"}),
                    status=200,
                    mimetype="application/json",
                )
                return EventDispatch(
                    events=["approval_approved"],
                    response=response,
                )

        # Event type not handled, return 200 OK to avoid retries
        response = Response(
            response=json.dumps({"message": "ok"}),
            status=200,
            mimetype="application/json",
        )
        return EventDispatch(response=response, events=[])
