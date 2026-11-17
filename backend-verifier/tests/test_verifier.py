"""Unit tests for Android Billing Zero-Trust Defense Verifier."""

import pytest
from fastapi import HTTPException

from app import (
    BillingDefenseService,
    ExternalAccountIdentifiers,
    IntegrityVerdict,
    OfferDetails,
    SubscriptionLineItem,
    SubscriptionPurchaseV2,
)


class MockIntegrityVerifier:
    def __init__(self, app_recognized: bool = True, device_integrity=None):
        self.app_recognized = app_recognized
        self.device_integrity = (
            device_integrity if device_integrity is not None else ["MEETS_DEVICE_INTEGRITY"]
        )

    def decode_and_verify(self, integrity_token: str) -> IntegrityVerdict:
        return IntegrityVerdict(
            app_recognized=self.app_recognized,
            device_integrity=self.device_integrity,
            request_hash="hash-123",
        )


class MockPlayApiClient:
    def __init__(self, subscription: SubscriptionPurchaseV2):
        self.subscription = subscription
        self.acknowledged = False
        self.revoked = False

    def get_subscription_v2(self, package_name: str, purchase_token: str) -> SubscriptionPurchaseV2:
        return self.subscription

    def acknowledge_subscription(self, package_name: str, product_id: str, purchase_token: str) -> None:
        self.acknowledged = True

    def revoke_subscription(self, package_name: str, purchase_token: str) -> None:
        self.revoked = True


def _build_service(play_api: MockPlayApiClient, integrity=None) -> BillingDefenseService:
    return BillingDefenseService(
        package_name="com.example.secureapp",
        hmac_secret=b"unit-test-secret-key",
        play_api=play_api,
        integrity_verifier=integrity or MockIntegrityVerifier(),
    )


def test_legitimate_purchase_without_offer_succeeds():
    play_api = MockPlayApiClient(
        SubscriptionPurchaseV2(
            subscriptionState="SUBSCRIPTION_STATE_ACTIVE",
            acknowledgementState="ACKNOWLEDGEMENT_STATE_PENDING",
            lineItems=[
                SubscriptionLineItem(
                    productId="pro_monthly",
                    offerDetails=OfferDetails(basePlanId="monthly-base", offerId=None),
                )
            ],
            externalAccountIdentifiers=None,
        )
    )
    svc = _build_service(play_api)

    # 1. Create checkout session
    session = svc.create_checkout_session(
        user_id="user-001",
        product_id="pro_monthly",
        base_plan_id="monthly-base",
        requested_offer_id=None,
        integrity_token="tok",
        expected_request_hash="hash-123",
    )

    # Bind Play response to the issued obfuscated_account_id
    play_api.subscription.externalAccountIdentifiers = ExternalAccountIdentifiers(
        obfuscatedExternalAccountId=session.obfuscated_account_id
    )

    # 2. Verify purchase
    result = svc.verify_and_grant_purchase(
        user_id="user-001",
        session_id=session.session_id,
        purchase_token="pt-valid",
    )
    assert result["status"] == "granted"
    assert play_api.acknowledged is True
    assert play_api.revoked is False


def test_unauthorized_offer_injection_is_blocked_and_revoked():
    """
    Simulates a client-side instrumentation attack where the backend authorized
    a standard paid plan (allowed_offer_id=None), but the client called
    launchBillingFlow with a $0 free-trial offerToken.
    """
    play_api = MockPlayApiClient(
        SubscriptionPurchaseV2(
            subscriptionState="SUBSCRIPTION_STATE_ACTIVE",
            acknowledgementState="ACKNOWLEDGEMENT_STATE_PENDING",
            lineItems=[
                SubscriptionLineItem(
                    productId="pro_monthly",
                    offerDetails=OfferDetails(
                        basePlanId="monthly-base",
                        offerId="zero-cost-trial-offer",  # Unauthorized!
                    ),
                )
            ],
            externalAccountIdentifiers=None,
        )
    )
    svc = _build_service(play_api)

    session = svc.create_checkout_session(
        user_id="user-002",
        product_id="pro_monthly",
        base_plan_id="monthly-base",
        requested_offer_id=None,
        integrity_token="tok",
        expected_request_hash="hash-123",
    )

    play_api.subscription.externalAccountIdentifiers = ExternalAccountIdentifiers(
        obfuscatedExternalAccountId=session.obfuscated_account_id
    )

    with pytest.raises(HTTPException) as exc_info:
        svc.verify_and_grant_purchase(
            user_id="user-002",
            session_id=session.session_id,
            purchase_token="pt-tampered",
        )
    assert exc_info.value.status_code == 403
    assert "Unauthorized offerId" in exc_info.value.detail
    assert play_api.acknowledged is False
    assert play_api.revoked is True
    assert "user-002" not in svc.granted_entitlements


def test_compromised_device_rejected_by_play_integrity():
    play_api = MockPlayApiClient(
        SubscriptionPurchaseV2(
            subscriptionState="SUBSCRIPTION_STATE_ACTIVE",
            acknowledgementState="ACKNOWLEDGEMENT_STATE_PENDING",
            lineItems=[],
        )
    )
    integrity = MockIntegrityVerifier(app_recognized=True, device_integrity=[])
    svc = _build_service(play_api, integrity=integrity)

    with pytest.raises(HTTPException) as exc_info:
        svc.create_checkout_session(
            user_id="user-003",
            product_id="pro_monthly",
            base_plan_id="monthly-base",
            requested_offer_id="welcome-trial",
            integrity_token="tok",
            expected_request_hash="hash-123",
        )
    assert exc_info.value.status_code == 403
    assert "Device failed integrity check" in exc_info.value.detail
