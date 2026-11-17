# 修复与加固指南（Remediation Guide）

针对客户端 `BillingClient` 进程内插桩与优惠越权风险，建议按照以下四个层级实施修复与加固。

---

## 1. Google Play Console 策略配置（源头收敛）

1. **合理设置优惠资格类型**：
   - 对于仅限首次订阅用户的优惠，在 Play Console 中明确配置为 **"New customer acquisition"（新客获取）**，由 Google Play 侧强制限制历史订阅用户不可见且不可用。
   - 对于需要业务侧判断的特殊活动（如特定等级会员、指定渠道试用），使用 **"Developer determined"（开发者自定义资格）**，切勿将其暴露为无条件公开优惠。
2. **控制服务端自动确认**：
   - 关闭或谨慎使用仅依赖客户端确认的流程，确保所有订阅必须在服务端校验通过后，由服务端调用 `purchases.subscriptionsv2.acknowledge`（或仅在服务端核验通过后下发权益，未确认的订单将在 3 天后由 Google Play 自动退款/取消）。

---

## 2. 服务端零信任核验（核心防御，必须实施）

### 2.1 结账前：签发绑定会话的 `obfuscatedAccountId`
在客户端调用 `launchBillingFlow` 之前，必须先向业务后端请求创建结账会话（Checkout Session）：
- 后端校验当前登录用户的历史权益、风控状态及 Play Integrity 令牌。
- 后端确定本次允许该用户购买的 `productId`、`basePlanId` 以及**唯一允许的 `offerId`**（若无试用资格，则 `allowed_offer_id` 为 `None`）。
- 后端生成一个短时效、防篡改的 `checkout_session_id`（或使用用户 ID 的 HMAC 派生值），作为 `obfuscatedAccountId` 返回给客户端。

### 2.2 结账后：使用 `subscriptionsv2.get` 核对全量字段
收到客户端上报的 `purchaseToken` 后，后端调用 Google Play Developer API `purchases.subscriptionsv2.get`：
1. **核验状态**：确认 `subscriptionState` 为 `SUBSCRIPTION_STATE_ACTIVE`（或处于合法宽限期）。
2. **核验账号绑定**：确认 `externalAccountIdentifiers.obfuscatedExternalAccountId` 与服务端记录的 `checkout_session_id` 一致。
3. **核验实际优惠 (`offerId`)**：
   - 读取 `lineItems[0].offerDetails.offerId`。
   - 如果服务端本次会话**未授权**任何优惠（或授权的是另一个 `offerId`），但订单中实际出现了未授权的试用 `offerId`，**立即拦截**！
   - 拒绝下发权益，并可调用 `purchases.subscriptionsv2.revoke` 主动撤销异常订单，同时触发风控告警。

### 2.3 接入实时开发者通知（RTDN）
通过 Google Cloud Pub/Sub 接收订阅生命周期事件（续费、取消、撤销、暂停），确保即使客户端不在线，服务端状态也能与 Google Play 保持最终一致。

---

## 3. Play Integrity API（设备与应用完整性校验）

在签发结账会话前要求客户端附带 Play Integrity Verdict：
- 验证 `appRecognitionVerdict == PLAY_RECOGNIZED`（确保是官方签名包，而非重打包 APK）。
- 验证 `deviceIntegrity` 包含 `MEETS_DEVICE_INTEGRITY`（或高安全场景下的 `MEETS_STRONG_INTEGRITY`），拦截 Root、模拟器或已知篡改环境发起的高价值试用请求。
- 使用 `requestHash` 将 Integrity Token 与当前用户 ID 及时间戳绑定，防止重放攻击。

---

## 4. 客户端安全编码与 RASP（纵深防御）

- **移除客户端本地资格硬编码**：客户端仅作为 UI 渲染层，所有优惠可用性由服务端接口下发。
- **Native 层 RASP 检测**（见 `android-defense-samples/`）：
  - 检测 `/proc/self/status` 中的 `TracerPid`（防调试）。
  - 扫描 `/proc/self/maps` 中的异常动态库或匿名可执行内存页。
  - 校验 APK 签名证书摘要，防止二次打包。
- **注意**：RASP 仅用于提高逆向与自动化脚本的攻击成本，**不能替代上述第 1、2 步的服务端核验**。
