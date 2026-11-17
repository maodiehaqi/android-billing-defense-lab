package com.example.secureapp.security

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Debug
import java.security.MessageDigest

/**
 * Defense-in-depth application-layer integrity checks (RASP).
 *
 * IMPORTANT: Client-side RASP raises the cost of casual tampering and
 * instrumentation, but it is NEVER a substitute for server-side verification
 * (Play Integrity API + Google Play Developer API subscriptionsv2).
 */
object RaspChecks {

    /**
     * Verifies the APK signing certificate SHA-256 digest against the expected
     * release certificate to detect repackaging.
     */
    @Suppress("DEPRECATION")
    fun verifySigningCertificate(context: Context, expectedSha256Hex: String): Boolean {
        return try {
            val pm = context.packageManager
            val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                val info = pm.getPackageInfo(
                    context.packageName,
                    PackageManager.GET_SIGNING_CERTIFICATES
                )
                info.signingInfo?.apkContentsSigners ?: emptyArray()
            } else {
                val info = pm.getPackageInfo(context.packageName, PackageManager.GET_SIGNATURES)
                info.signatures ?: emptyArray()
            }

            val digest = MessageDigest.getInstance("SHA-256")
            signatures.any { sig ->
                val hash = digest.digest(sig.toByteArray())
                    .joinToString("") { "%02x".format(it) }
                hash.equals(expectedSha256Hex, ignoreCase = true)
            }
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Checks if a Java/JDWP debugger is attached.
     */
    fun isDebuggerAttached(): Boolean {
        return Debug.isDebuggerConnected() || Debug.waitingForDebugger()
    }
}
