package com.example.secureapp.billing

import android.app.Activity
import com.android.billingclient.api.BillingClient
import com.android.billingclient.api.BillingFlowParams
import com.android.billingclient.api.ProductDetails
import com.android.billingclient.api.Purchase

/**
 * Reference implementation of a Zero-Trust Android BillingClient wrapper.
 *
 * Key defensive properties:
 * 1. Never evaluates promotional/trial eligibility locally.
 * 2. Requires a backend-issued checkout session (bound via obfuscatedAccountId)
 *    and Play Integrity verification before calling launchBillingFlow.
 * 3. Filters ProductDetails.subscriptionOfferDetails strictly against the
 *    server-authorized offerId.
 * 4. Never acknowledges purchases or grants entitlements on the client;
 *    delegates verification and acknowledgement exclusively to the backend.
 */
class SecureBillingManager(
    private val billingClient: BillingClient,
    private val backendApi: BillingBackendApi,
    private val integrityProvider: PlayIntegrityProvider
) {

    data class CheckoutSessionResponse(
        val sessionId: String,
        val obfuscatedAccountId: String,
        val allowedOfferId: String?
    )

    interface BillingBackendApi {
        suspend fun createCheckoutSession(
            productId: String,
            basePlanId: String,
            requestedOfferId: String?,
            integrityToken: String,
            requestHash: String
        ): CheckoutSessionResponse

        suspend fun verifyPurchaseOnServer(
            sessionId: String,
            purchaseToken: String
        ): Boolean
    }

    interface PlayIntegrityProvider {
        suspend fun requestIntegrityToken(requestHash: String): String
    }

    suspend fun startSecureSubscriptionFlow(
        activity: Activity,
        productDetails: ProductDetails,
        basePlanId: String,
        requestedOfferId: String?
    ): Result<String> {
        val requestHash = "${productDetails.productId}:$basePlanId:${System.currentTimeMillis()}"
        val integrityToken = integrityProvider.requestIntegrityToken(requestHash)

        // 1. Obtain server-authorized checkout session & obfuscatedAccountId
        val session = backendApi.createCheckoutSession(
            productId = productDetails.productId,
            basePlanId = basePlanId,
            requestedOfferId = requestedOfferId,
            integrityToken = integrityToken,
            requestHash = requestHash
        )

        // 2. Match only the exact offerId authorized by the backend
        val offerDetails = productDetails.subscriptionOfferDetails?.firstOrNull { offer ->
            offer.basePlanId == basePlanId && offer.offerId == session.allowedOfferId
        } ?: return Result.failure(IllegalStateException("Authorized offer not found in ProductDetails"))

        val productParams = BillingFlowParams.ProductDetailsParams.newBuilder()
            .setProductDetails(productDetails)
            .setOfferToken(offerDetails.offerToken)
            .build()

        // 3. Bind the Play transaction to the server session via obfuscatedAccountId
        val flowParams = BillingFlowParams.newBuilder()
            .setProductDetailsParamsList(listOf(productParams))
            .setObfuscatedAccountId(session.obfuscatedAccountId)
            .build()

        val result = billingClient.launchBillingFlow(activity, flowParams)
        return if (result.responseCode == BillingClient.BillingResponseCode.OK) {
            Result.success(session.sessionId)
        } else {
            Result.failure(IllegalStateException("Billing flow failed: ${result.debugMessage}"))
        }
    }

    /**
     * Called from PurchasesUpdatedListener.
     * Note: Client NEVER calls billingClient.acknowledgePurchase() directly.
     * The backend verifies subscriptionsv2.get (including offerId & account binding)
     * and performs acknowledgement server-side.
     */
    suspend fun handlePurchaseUpdate(sessionId: String, purchase: Purchase): Boolean {
        if (purchase.purchaseState != Purchase.PurchaseState.PURCHASED) {
            return false
        }
        return backendApi.verifyPurchaseOnServer(
            sessionId = sessionId,
            purchaseToken = purchase.purchaseToken
        )
    }
}
