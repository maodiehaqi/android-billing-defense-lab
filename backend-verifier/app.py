"""
Android Billing Zero-Trust Backend Verifier (Reference Implementation)

Demonstrates how to defend against client-side BillingClient tampering
(e.g. unauthorized offerToken / free-trial injection via instrumentation):
1. Issue server-side checkout sessions bound via obfuscatedAccountId.
2. Verify Play Integrity verdict before authorizing promotional offers.
3. Verify Google Play subscriptionsv2.get response on the backend:
   - Check subscriptionState
   - Check externalAccountIdentifiers.obfuscatedExternalAccountId
   - Check lineItems[].offerDetails.offerId against server-authorized offer
4. Gate entitlement & acknowledgement strictly on backend verification.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Protocol

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Domain Models & Interfaces
# ---------------------------------------------------------------------------


class OfferDetails(BaseModel):
    basePlanId: str
    offerId: Optional[str] = None


class SubscriptionLineItem(BaseModel):
    productId: str
    offerDetails: OfferDetails


class ExternalAccountIdentifiers(BaseModel):
    obfuscatedExternalAccountId: Optional[str] = None
    obfuscatedExternalProfileId: Optional[str] = None


class SubscriptionPurchaseV2(BaseModel):
    subscriptionState: str
    acknowledgementState: str
    lineItems: List[SubscriptionLineItem]
    externalAccountIdentifiers: Optional[ExternalAccountIdentifiers] = None


class IntegrityVerdict(BaseModel):
    app_recognized: bool
    device_integrity: List[str]
    request_hash: str


class PlayDeveloperApiClient(Protocol):
    """Abstraction over Google Play Developer API (subscriptionsv2)."""

    def get_subscription_v2(self, package_name: str, purchase_token: str) -> SubscriptionPurchaseV2:
        ...

    def acknowledge_subscription(self, package_name: str, product_id: str, purchase_token: str) -> None:
        ...

    def revoke_subscription(self, package_name: str, purchase_token: str) -> None:
        ...


class PlayIntegrityVerifier(Protocol):
    """Abstraction over Google Play Integrity API."""

    def decode_and_verify(self, integrity_token: str) -> IntegrityVerdict:
        ...


# ---------------------------------------------------------------------------
# In-Memory Store & Security Services (Replace with Redis/DB in production)
# ---------------------------------------------------------------------------


@dataclass
class CheckoutSession:
    session_id: str
    user_id: str
    product_id: str
    base_plan_id: str
    allowed_offer_id: Optional[str]
    obfuscated_account_id: str
    expires_at: float
    consumed: bool = False


class BillingDefenseService:
    def __init__(
        self,
        package_name: str,
        hmac_secret: bytes,
        play_api: PlayDeveloperApiClient,
        integrity_verifier: PlayIntegrityVerifier,
    ) -> None:
        self.package_name = package_name
        self.hmac_secret = hmac_secret
        self.play_api = play_api
        self.integrity_verifier = integrity_verifier
        self.sessions: Dict[str, CheckoutSession] = {}
        self.user_trial_history: Dict[str, bool] = {}
        self.granted_entitlements: Dict[str, str] = {}

    def _derive_obfuscated_account_id(self, user_id: str, session_id: str) -> str:
        """Bind Play order to internal user + session without exposing PII."""
        payload = f"{user_id}:{session_id}".encode("utf-8")
        digest = hmac.new(self.hmac_secret, payload, hashlib.sha256).hexdigest()
        return digest[:48]

    def create_checkout_session(
        self,
        user_id: str,
        product_id: str,
        base_plan_id: str,
        requested_offer_id: Optional[str],
        integrity_token: str,
        expected_request_hash: str,
    ) -> CheckoutSession:
        # 1. Verify Play Integrity verdict
        verdict = self.integrity_verifier.decode_and_verify(integrity_token)
        if not verdict.app_recognized:
            raise HTTPException(status_code=403, detail="Unrecognized application binary.")
        if "MEETS_DEVICE_INTEGRITY" not in verdict.device_integrity:
            raise HTTPException(status_code=403, detail="Device failed integrity check.")
        if not hmac.compare_digest(verdict.request_hash, expected_request_hash):
            raise HTTPException(status_code=403, detail="Integrity requestHash mismatch.")

        # 2. Server-side eligibility enforcement (Never trust client!)
        has_used_trial = self.user_trial_history.get(user_id, False)
        if requested_offer_id is not None and has_used_trial:
            raise HTTPException(
                status_code=403,
                detail="User is not eligible for promotional/trial offer.",
            )

        session_id = secrets.token_urlsafe(16)
        obfuscated_id = self._derive_obfuscated_account_id(user_id, session_id)
        session = CheckoutSession(
            session_id=session_id,
            user_id=user_id,
            product_id=product_id,
            base_plan_id=base_plan_id,
            allowed_offer_id=requested_offer_id,
            obfuscated_account_id=obfuscated_id,
            expires_at=time.time() + 900,  # 15 minutes TTL
        )
        self.sessions[session_id] = session
        return session

    def verify_and_grant_purchase(
        self,
        user_id: str,
        session_id: str,
        purchase_token: str,
    ) -> dict:
        session = self.sessions.get(session_id)
        if not session or session.user_id != user_id:
            raise HTTPException(status_code=404, detail="Checkout session not found.")
        if session.consumed:
            raise HTTPException(status_code=409, detail="Checkout session already consumed.")
        if time.time() > session.expires_at:
            raise HTTPException(status_code=410, detail="Checkout session expired.")

        # 1. Query authoritative subscription state from Google Play Developer API
        sub = self.play_api.get_subscription_v2(self.package_name, purchase_token)

        if sub.subscriptionState != "SUBSCRIPTION_STATE_ACTIVE":
            raise HTTPException(
                status_code=400,
                detail=f"Subscription is not active: {sub.subscriptionState}",
            )

        # 2. Verify obfuscatedExternalAccountId matches this exact session
        actual_obfuscated_id = (
            sub.externalAccountIdentifiers.obfuscatedExternalAccountId
            if sub.externalAccountIdentifiers
            else None
        )
        if not actual_obfuscated_id or not hmac.compare_digest(
            actual_obfuscated_id, session.obfuscated_account_id
        ):
            raise HTTPException(
                status_code=403,
                detail="Account binding mismatch: possible token replay or tampering.",
            )

        # 3. Verify productId, basePlanId, and offerId against server-authorized values
        if not sub.lineItems:
            raise HTTPException(status_code=400, detail="Missing subscription line items.")

        item = sub.lineItems[0]
        if item.productId != session.product_id or item.offerDetails.basePlanId != session.base_plan_id:
            self.play_api.revoke_subscription(self.package_name, purchase_token)
            raise HTTPException(
                status_code=403,
                detail="Product or basePlanId mismatch; subscription revoked.",
            )

        if item.offerDetails.offerId != session.allowed_offer_id:
            # Critical defense: Client injected an unauthorized offerToken (e.g., $0 trial)
            self.play_api.revoke_subscription(self.package_name, purchase_token)
            raise HTTPException(
                status_code=403,
                detail="Unauthorized offerId detected; entitlement denied and subscription revoked.",
            )

        # 4. Acknowledge purchase on backend and grant entitlement
        if sub.acknowledgementState != "ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED":
            self.play_api.acknowledge_subscription(
                self.package_name, item.productId, purchase_token
            )

        session.consumed = True
        if session.allowed_offer_id is not None:
            self.user_trial_history[user_id] = True
        self.granted_entitlements[user_id] = item.productId

        return {
            "status": "granted",
            "user_id": user_id,
            "product_id": item.productId,
            "offer_id": item.offerDetails.offerId,
        }


# ---------------------------------------------------------------------------
# FastAPI App Wiring (with stub adapters for standalone demo)
# ---------------------------------------------------------------------------


class DemoPlayApiClient:
    def get_subscription_v2(self, package_name: str, purchase_token: str) -> SubscriptionPurchaseV2:
        raise NotImplementedError("Wire real Google Play Developer API client in production.")

    def acknowledge_subscription(self, package_name: str, product_id: str, purchase_token: str) -> None:
        pass

    def revoke_subscription(self, package_name: str, purchase_token: str) -> None:
        pass


class DemoIntegrityVerifier:
    def decode_and_verify(self, integrity_token: str) -> IntegrityVerdict:
        raise NotImplementedError("Wire real Play Integrity API client in production.")


class CreateSessionRequest(BaseModel):
    user_id: str = Field(..., min_length=1)
    product_id: str = Field(..., min_length=1)
    base_plan_id: str = Field(..., min_length=1)
    requested_offer_id: Optional[str] = None
    integrity_token: str = Field(..., min_length=1)
    request_hash: str = Field(..., min_length=1)


class VerifyPurchaseRequest(BaseModel):
    user_id: str = Field(..., min_length=1)
    session_id: str = Field(..., min_length=1)
    purchase_token: str = Field(..., min_length=1)


def create_app(service: Optional[BillingDefenseService] = None) -> FastAPI:
    app = FastAPI(title="Android Billing Zero-Trust Defense Verifier")
    svc = service or BillingDefenseService(
        package_name="com.example.secureapp",
        hmac_secret=b"replace-with-kms-managed-secret",
        play_api=DemoPlayApiClient(),
        integrity_verifier=DemoIntegrityVerifier(),
    )

    @app.post("/v1/billing/checkout-session")
    def create_checkout_session(req: CreateSessionRequest) -> dict:
        session = svc.create_checkout_session(
            user_id=req.user_id,
            product_id=req.product_id,
            base_plan_id=req.base_plan_id,
            requested_offer_id=req.requested_offer_id,
            integrity_token=req.integrity_token,
            expected_request_hash=req.request_hash,
        )
        return {
            "session_id": session.session_id,
            "obfuscated_account_id": session.obfuscated_account_id,
            "allowed_offer_id": session.allowed_offer_id,
        }

    @app.post("/v1/billing/verify-purchase")
    def verify_purchase(req: VerifyPurchaseRequest) -> dict:
        return svc.verify_and_grant_purchase(
            user_id=req.user_id,
            session_id=req.session_id,
            purchase_token=req.purchase_token,
        )

    return app


app = create_app()
