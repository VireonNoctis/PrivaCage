# 15 — Cellular Network Downgrade Risk and Android 2G Protection

**Research status:** Android platform review, 8 November 2026  
**Decision this note supports:** provide a useful warning for legacy cellular generations without pretending an ordinary app can inspect modem encryption or force radio policy.

## 1. Threat model

A false base station can attempt to lure a device onto an older cellular network, commonly 2G. A successful 2G downgrade can expose traffic to interception or injection because legacy 2G authentication and encryption protections are weaker. This is a real protocol/platform risk; it does not justify treating every weak-signal event, network switch, carrier or company as evidence of an attack.

The product must distinguish:

- **Observed radio generation:** the packet-switched network type reported by Android.
- **Cipher/security state:** whether the modem reports an encrypted or unencrypted connection.
- **Suspected false base station:** a separate security hypothesis requiring modem/network evidence.
- **Mitigation configured:** whether the user has disabled 2G in the operating system for each SIM.

A 2G generation report is not itself proof that the network is unencrypted or malicious. A non-2G report is not proof that the connection is encrypted or that no false base station is present.

## 2. What Android lets a normal app do

### 2.1 Radio-generation observation

Android 12/API 31 exposes TelephonyCallback.DisplayInfoListener. Its TelephonyDisplayInfo.getNetworkType() value reports the packet-switched cellular network type. PrivaCage uses this callback only while its main activity is resumed and classifies:

- GPRS, EDGE and GSM as **GSM 2G reported** (prominent warning).
- CDMA, 1xRTT and iDEN as **legacy 2G-class technology** (separate caution, not conflated with GSM).
- Other known network types as **no GSM 2G indication in the reported packet-data type**.
- Unknown, unavailable and unsupported values as **unverified**, never as “safe”.

This observer uses the default TelephonyManager subscription only. It does not claim to cover every SIM, voice-only service, emergency service, roaming path, modem state or all OEM implementations. The platform API describes a packet-switched network type; it does not report the radio cipher/encryption algorithm or detect a false base station.

The callback is unregistered when PrivaCage pauses. No cell scan, cell identity, signal-strength history, location, background worker, notification or persistent radio history is collected.

### 2.2 Disabling 2G belongs to Android Settings

Android 12 introduced a 2G toggle for devices whose modem implements the required radio capability. On supported devices, disabling 2G prevents normal scanning/connection to 2G at the radio layer. The control is per SIM. Emergency calling is explicitly preserved by the platform.

An ordinary third-party application cannot silently or directly force this policy. Android's TelephonyManager.setAllowedNetworkTypesForReason() requires MODIFY_PHONE_STATE or carrier privileges; from Android 14, 2G-specific changes with the enable-2G reason require privileged phone-state authority. PrivaCage therefore opens Android's wireless/mobile-network settings and leaves the change to the user.

Android 16 renamed the SIM control to “2G network protection” and changed the toggle's visual/default-state semantics to match the label without changing the underlying default 2G connectivity. The user must read the on-screen description rather than infer protection from switch position alone. The exact menu path remains OEM-dependent.

### 2.3 Native unencrypted-network alerts

Android 16 adds a Mobile network security area in Safety Center on devices that support both the 2G toggle and modem security notifications. Compatible IRadio 3.0 implementations can notify when the device connects to an unencrypted network or exchanges identifiers such as IMSI/IMEI. The notifications switch is OFF by default. PrivaCage links to Android's security settings so the user can review it; the app does not claim to enable or read that system setting.

These native system alerts are a better evidence source for cipher/identifier events than guessing from signal bars or a network-generation label. They are still modem/OEM-dependent.

## 3. Why Accessibility access is not requested

Android AccessibilityService receives user-interface AccessibilityEvents and can optionally inspect active-window content. It is intended to assist users with disabilities. It does not expose modem registration, cellular cipher algorithms, allowed-network bitmasks or radio-policy controls.

Requesting Accessibility access for this feature would be unrelated to the threat and would grant broad access to sensitive UI state without improving 2G protection. PrivaCage does not add an Accessibility Service or request that permission.

## 4. User-facing behavior

At the top of the experimental Android app:

1. Show the reported packet-data network type and status.
2. Raise a visible warning for GPRS, EDGE or GSM.
3. Keep legacy CDMA/1xRTT/iDEN in a separate caution category.
4. Show “unknown/unavailable” rather than a green state if Android cannot report a type.
5. Provide explicit Settings actions:
   - Review 2G protection for every SIM in Mobile network settings.
   - Review Android's unencrypted-network alerts in Security/Safety Center settings.
6. Always explain that the app cannot inspect cipher state or prove a false base station.

The warning is informational; it does not block calls/data, modify radio configuration, replace Android's notifications or guarantee protection.

## 5. Validation still required

- Build and unit-test classifier mapping for GSM 2G, legacy 2G-class, ordinary newer types and unknown.
- Run on Android 12–16 physical devices from multiple OEMs and carriers.
- Check dual-SIM/eSIM and default-data-SIM changes.
- Check no-radio tablets, Wi-Fi-only operation, no-service state and callback permission failures.
- Confirm lifecycle unregistration on activity pause/destroy.
- Verify actual 2G toggle availability and native unencrypted-network notification support manually on compatible devices.
- Do not infer success from emulator results; modem capabilities and RIL/IRadio support are required for full verification.

## 6. Evidence and limits

Primary sources are linked in SOURCES.md under S33–S39. This is engineering research, not a claim that any particular carrier, business or government actor is operating a false base station. The app is an experimental warning aid, not a cellular intrusion detector or radio firewall.
