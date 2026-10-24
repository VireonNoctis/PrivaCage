package org.privacage.android.sync

/**
 * JNI facade for the shared Rust sync protocol.
 * Cryptographic operations are provided by pcage-sync, not reimplemented in Kotlin.
 */
internal class NativeSyncBridge {
    init {
        try {
            System.loadLibrary("pcage_sync_jni")
        } catch (error: UnsatisfiedLinkError) {
            throw IllegalStateException(
                "The PrivaCage sync native library is missing. Build it with cargo-ndk before running the Android app.",
                error
            )
        }
    }

    external fun nativeCreateIdentity(localPassphrase: String): String
    external fun nativeRestoreIdentity(localBundleBase64: String, localPassphrase: String): String
    external fun nativeVerifyIdentityCard(cardJson: String): String
    external fun nativeRotateIdentity(
        localBundleBase64: String,
        localPassphrase: String,
        nextLocalPassphrase: String
    ): String
    external fun nativeVerifyKeyRotation(
        previousCardJson: String,
        rotationJson: String,
        nowUnix: Long
    ): String
    external fun nativeCreateDeviceRoster(
        localBundleBase64: String,
        localPassphrase: String,
        spaceId: String,
        revision: Long,
        issuedAtUnix: Long,
        membersJson: String
    ): String
    external fun nativeVerifyDeviceRoster(
        rosterJson: String,
        expectedOwnerFingerprint: String,
        minimumRevision: Long,
        nowUnix: Long
    ): String
    external fun nativeSignRelayRequest(
        localBundleBase64: String,
        localPassphrase: String,
        method: String,
        pathAndQuery: String,
        timestampUnix: Long,
        nonce: String,
        body: String
    ): String

    external fun nativeSealPacket(
        localBundleBase64: String,
        localPassphrase: String,
        recipientCardJson: String,
        profilePayloadJson: String,
        sequence: Long,
        nowUnix: Long,
        ttlSeconds: Long
    ): String

    external fun nativeOpenPacket(
        localBundleBase64: String,
        localPassphrase: String,
        senderCardJson: String,
        packetJson: String,
        nowUnix: Long,
        replayLedgerPath: String
    ): String

    external fun nativeExportRecoveryBundle(
        localBundleBase64: String,
        localPassphrase: String,
        recoveryPassphrase: String
    ): String

    external fun nativeImportRecoveryBundle(
        recoveryBundleBase64: String,
        recoveryPassphrase: String,
        localPassphrase: String
    ): String
}
