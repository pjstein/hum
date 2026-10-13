package hum.blst.runtime

import android.app.Activity
import android.app.Instrumentation
import android.os.Bundle
import uniffi.hum_android_blst_probe.runProbe

/** Synthetic-only test APK: exercises generated Kotlin, JNA, UniFFI and blst. */
class ProbeInstrumentation : Instrumentation() {
    override fun onCreate(arguments: Bundle?) {
        super.onCreate(arguments)
        start()
    }

    override fun onStart() {
        val result = Bundle()
        try {
            // Repeat to exercise native buffer transfer/free beyond initialization.
            repeat(20) {
                val probe = runProbe()
                check(probe.validSignature)
                check(probe.alteredMessageRejected)
                check(probe.malformedPublicKeyRejected)
                check(probe.malformedSignatureRejected)
                check(probe.publicKeyBytes == 48u)
                check(probe.signatureBytes == 96u)
            }
            result.putString("hum_result", "PASS: 20 Kotlin-UniFFI-blst calls, 120 assertions")
            finish(Activity.RESULT_OK, result)
        } catch (failure: Throwable) {
            result.putString("hum_result", "FAIL: ${failure.stackTraceToString()}")
            finish(Activity.RESULT_CANCELED, result)
        }
    }
}
