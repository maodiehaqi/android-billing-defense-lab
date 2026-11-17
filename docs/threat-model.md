# 威胁模型：Android 应用内计费（BillingClient）客户端篡改风险

## 1. 概述

在现代移动应用商业化中，Google Play Billing Library (`BillingClient`) 是处理订阅与应用内购买的标准 SDK。然而，客户端运行在用户完全可控的设备环境中，任何仅在客户端执行的业务校验都不构成真正的安全边界。

## 2. 核心风险点

### 2.1 客户端资格判断与 `offerToken` 暴露
Google Play 支持为同一基础订阅计划（Base Plan）配置多个优惠方案（Offers），例如：
- 首月 `$0` 免费试用（Free Trial）
- 新用户首期折扣（Introductory Pricing）
- 特定渠道或开发者自定义资格的促销优惠（Developer-determined Offers）

当客户端调用 `BillingClient.queryProductDetailsAsync()` 时，SDK 会返回该商品下所有对当前 Play 账号可见的 `SubscriptionOfferDetails` 列表，每个对象包含一个不透明的 `offerToken`。

**常见错误实现：**
- 客户端在 UI 层根据本地接口返回值隐藏了“免费试用”按钮，但未在服务端对“开发者自定义优惠（Developer-determined Offer）”做强绑定校验。
- 在受控设备（如已 Root 设备）上，运行在同进程内的动态插桩工具可以遍历内存中的 `BillingClient` 实例与 `ProductDetails` 对象，直接用非预期的 `offerToken` 发起 `launchBillingFlow()`。

### 2.2 后端校验粒度不足（仅校验状态，不校验优惠详情）
部分后端服务在收到客户端上传的 `purchaseToken` 后，仅调用 Google Play Developer API 检查订单是否为 `SUBSCRIPTION_STATE_ACTIVE`，而忽略了以下关键字段：
- `lineItems[].offerDetails.offerId`（实际生效的优惠 ID）
- `lineItems[].offerDetails.basePlanId`（实际生效的基础方案）
- `externalAccountIdentifiers.obfuscatedExternalAccountId`（订单与业务账号/结账会话的绑定关系）

这会导致即使客户端发起了未经授权的促销或免费试用订单，后端依然会“照单全收”并下发完整权益。

### 2.3 客户端本地确认（Acknowledge）与权益下发
如果在客户端直接调用 `BillingClient.acknowledgePurchase()` 并根据 `BillingResult.OK` 解锁本地功能或通知后端“已购买”，攻击者可以通过 Hook 回调或伪造本地状态绕过付费流程。

## 3. 安全边界划分

| 组件 | 信任级别 | 允许承担的职责 | 禁止承担的职责 |
| :--- | :--- | :--- | :--- |
| Android 客户端 | **不可信 (Untrusted)** | 展示服务端下发的商品/优惠选项、拉起 Google Play 支付界面、传递 `purchaseToken` | 独立决定用户是否有权享受 `$0` 试用、直接解锁付费权益、单独完成订单确认 |
| Google Play 服务 | **受控第三方 (Trusted Partner)** | 托管支付流程、生成加密 `purchaseToken`、提供 Developer API 与 RTDN 通知 | 替业务方判断复杂的业务侧自定义促销资格 |
| 业务后端服务 | **可信边界 (Trusted Boundary)** | 资格审查、签发结账会话 ID、调用 Play API 核验订单与 `offerId`、控制订单确认与权益下发 | 无条件信任客户端上报的 SKU、价格或优惠 ID |
