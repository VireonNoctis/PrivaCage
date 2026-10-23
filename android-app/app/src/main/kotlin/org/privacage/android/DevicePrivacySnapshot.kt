package org.privacage.android

/**
 * Data shape for the local device privacy snapshot.
 *
 * Values are displayed on-device only. The snapshot intentionally excludes Wi-Fi SSIDs,
 * scan results, location coordinates, installed-app inventories, and network uploads.
 */
internal data class DevicePrivacySnapshot(
    val locationServices: String,
    val wifiRadio: String,
    val privateDns: String,
    val activeDefaultNetworkVpn: String
)
