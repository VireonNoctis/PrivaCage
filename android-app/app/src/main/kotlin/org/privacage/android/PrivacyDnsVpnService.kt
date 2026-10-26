package org.privacage.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import org.privacage.dns.DnsPacketProcessor
import org.privacage.dns.DnsRouteDiagnostic
import org.privacage.dns.DnsPolicyEngine
import org.privacage.dns.DnsTunnelEngine
import org.privacage.dns.DnsTunnelResult
import org.privacage.dns.DnsTunnelStatsSnapshot
import org.privacage.dns.DnsOverTlsForwarder
import org.privacage.dns.DnsUpstreamTransport
import org.privacage.dns.TcpSocketProtector
import org.privacage.dns.UdpDnsForwarder
import org.privacage.dns.UdpSocketProtector
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.time.Instant
import java.util.concurrent.atomic.AtomicBoolean
import java.util.UUID

class PrivacyDnsVpnService : VpnService() {
    @Volatile private var running = false
    @Volatile private var tunnel: ParcelFileDescriptor? = null
    @Volatile private var diagnosticForwarder: DnsUpstreamTransport? = null
    private val diagnosticRunning = AtomicBoolean(false)

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_RUN_DIAGNOSTIC) {
            runDnsRouteDiagnostic()
            return START_NOT_STICKY
        }
        if (intent?.action != ACTION_START) {
            stopSelf(startId)
            return START_NOT_STICKY
        }
        if (running) return START_NOT_STICKY
        publishState(
            VpnSessionStatus.STATE_STARTING,
            "Start requested; validating configuration and establishing the virtual DNS interface."
        )

        try {
            val prefs = getSharedPreferences(PREFERENCES_NAME, MODE_PRIVATE)
            val resolverText = prefs.getString(KEY_RESOLVER_IP, "").orEmpty()
            val domains = prefs.getStringSet(KEY_BLOCKED_DOMAINS, emptySet()).orEmpty()
            require(isIpv4Address(resolverText)) { "A numeric IPv4 resolver must be configured" }
            require(domains.isNotEmpty()) { "At least one blocked domain must be configured" }

            val policy = DnsPolicyEngine(domains)
            val resolverAddress = InetAddress.getByName(resolverText)
            val dnsOverTlsEnabled = prefs.getBoolean(KEY_DOT_ENABLED, false)
            val dnsOverTlsHostname = prefs.getString(KEY_DOT_HOSTNAME, "").orEmpty()
            val forwarder = createForwarder(
                resolverAddress,
                dnsOverTlsEnabled,
                dnsOverTlsHostname,
                policy
            )
            // The one-shot diagnostic tests upstream reachability independently of the user's
            // blocklist, while using the same resolver, transport, certificate checks and
            // protected sockets as live filtering.
            val diagnosticTransport = createForwarder(
                resolverAddress,
                dnsOverTlsEnabled,
                dnsOverTlsHostname,
                DnsPolicyEngine(emptySet())
            )
            val engine = DnsTunnelEngine(DnsPacketProcessor(policy), forwarder)
            val descriptor = Builder()
                .setSession("PrivaCage DNS filtering")
                .setMtu(1500)
                .addAddress(VPN_INTERFACE_ADDRESS, 32)
                .addDnsServer(VIRTUAL_DNS_ADDRESS)
                .addRoute(VIRTUAL_DNS_ADDRESS, 32)
                // IPv6 clients receive a separate virtual DNS target. The route remains /128;
                // general IPv6 traffic is not pulled into this DNS-only VPN.
                .addAddress(VPN_IPV6_INTERFACE_ADDRESS, 128)
                .addDnsServer(VIRTUAL_IPV6_DNS_ADDRESS)
                .addRoute(VIRTUAL_IPV6_DNS_ADDRESS, 128)
                .setBlocking(true)
                .establish() ?: throw IOException("Android refused to establish the VPN interface")

            tunnel = descriptor
            diagnosticForwarder = diagnosticTransport
            running = true
            persistStats(engine.stats.snapshot())
            startVpnForeground()
            Thread({
                publishState(
                    VpnSessionStatus.STATE_ACTIVE,
                    "The virtual DNS interface was established and the packet loop started."
                )
                pumpPackets(descriptor, engine)
            }, "PrivaCage-DNS-TUN").apply {
                isDaemon = true
                start()
            }
        } catch (exception: Exception) {
            Log.e(TAG, "DNS VPN could not start", exception)
            running = false
            diagnosticForwarder = null
            closeTunnel()
            stopForeground(STOP_FOREGROUND_REMOVE)
            publishState(
                VpnSessionStatus.STATE_ERROR,
                "DNS filtering could not start. Check configuration and Android VPN permissions."
            )
            postFailureNotification("DNS filtering could not start. Check configuration and Android VPN permissions.")
            stopSelf(startId)
        }
        return START_NOT_STICKY
    }

    override fun onRevoke() {
        running = false
        closeTunnel()
        stopForeground(STOP_FOREGROUND_REMOVE)
        publishState(VpnSessionStatus.STATE_STOPPED, "Android revoked VPN access; DNS filtering is stopped.")
        super.onRevoke()
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }

    private fun pumpPackets(descriptor: ParcelFileDescriptor, engine: DnsTunnelEngine) {
        val input = FileInputStream(descriptor.fileDescriptor)
        val output = FileOutputStream(descriptor.fileDescriptor)
        val buffer = ByteArray(MAX_IP_PACKET_SIZE)
        var packetsSinceStatsFlush = 0
        var failureMessage: String? = null

        try {
            while (running) {
                val count = input.read(buffer)
                if (count < 0) break
                if (count == 0) continue

                val packet = buffer.copyOf(count)
                val result = try {
                    engine.processIpPacket(packet)
                } catch (exception: IOException) {
                    if (running) {
                        // An upstream timeout should drop one DNS request, not tear down the VPN.
                        Log.w(TAG, "Upstream DNS request failed; dropping this query while keeping the tunnel active.", exception)
                    }
                    packetsSinceStatsFlush += 1
                    if (packetsSinceStatsFlush >= STATS_FLUSH_PACKET_INTERVAL) {
                        persistStats(engine.stats.snapshot())
                        packetsSinceStatsFlush = 0
                    }
                    continue
                }

                when (result) {
                    is DnsTunnelResult.Response -> {
                        if (result.domain.isNotBlank()) {
                            when (LocalDnsEventHistory.record(this, packet, result.domain, result.action.name)) {
                                LocalDnsEventHistory.RecordResult.HISTORY_UNREADABLE -> Log.w(
                                    TAG,
                                    "Local DNS history is unreadable; saved data was preserved and this event was not recorded. Review or clear history from the DNS history view."
                                )
                                LocalDnsEventHistory.RecordResult.DISABLED,
                                LocalDnsEventHistory.RecordResult.RECORDED -> Unit
                            }
                        }
                        output.write(result.packet)
                        output.flush()
                    }
                    is DnsTunnelResult.Drop -> {
                        Log.w(TAG, "Dropped malformed/unsupported DNS packet: " + result.reason)
                    }
                    is DnsTunnelResult.NotDns -> {
                        // The VPN route is limited to the virtual DNS endpoint.
                    }
                }
                packetsSinceStatsFlush += 1
                if (packetsSinceStatsFlush >= STATS_FLUSH_PACKET_INTERVAL) {
                    persistStats(engine.stats.snapshot())
                    packetsSinceStatsFlush = 0
                }
            }
        } catch (exception: IOException) {
            if (running) {
                failureMessage = "DNS filtering stopped after a tunnel I/O error."
                Log.e(TAG, "DNS packet loop stopped after a tunnel I/O failure", exception)
            }
        } catch (exception: RuntimeException) {
            failureMessage = "DNS filtering stopped after an internal packet-processing error."
            Log.e(TAG, "DNS packet loop stopped after a processing failure", exception)
        } finally {
            persistStats(engine.stats.snapshot())
            running = false
            diagnosticForwarder = null
            closeTunnel()
            stopForeground(STOP_FOREGROUND_REMOVE)
            if (failureMessage != null) {
                publishState(VpnSessionStatus.STATE_ERROR, failureMessage)
                postFailureNotification(failureMessage)
            } else {
                publishState(VpnSessionStatus.STATE_STOPPED, "DNS filtering stopped.")
            }
            stopSelf()
        }
    }

    private fun createForwarder(
        resolverAddress: InetAddress,
        dnsOverTlsEnabled: Boolean,
        dnsOverTlsHostname: String,
        policyEngine: DnsPolicyEngine
    ): DnsUpstreamTransport {
        return if (dnsOverTlsEnabled) {
            require(dnsOverTlsHostname.isNotBlank()) { "DNS-over-TLS requires a certificate hostname" }
            DnsOverTlsForwarder(
                resolverAddress = resolverAddress,
                tlsHostname = dnsOverTlsHostname,
                socketProtector = TcpSocketProtector { socket: Socket -> protect(socket) },
                policyEngine = policyEngine
            )
        } else {
            UdpDnsForwarder(
                resolver = InetSocketAddress(resolverAddress, DNS_PORT),
                socketProtector = UdpSocketProtector { socket: DatagramSocket -> protect(socket) },
                policyEngine = policyEngine,
                tcpSocketProtector = TcpSocketProtector { socket: Socket -> protect(socket) }
            )
        }
    }

    private fun runDnsRouteDiagnostic() {
        val transport = diagnosticForwarder
        if (!running || transport == null) {
            persistDiagnosticFailure(
                "PrivaCage DNS filtering is not active. Enable it before testing the configured resolver path."
            )
            sendDiagnosticResultBroadcast()
            stopSelf()
            return
        }
        if (!diagnosticRunning.compareAndSet(false, true)) return

        Thread({
            try {
                val networkAtStart = DnsNetworkSnapshot.capture(this)
                val preferences = getSharedPreferences(PREFERENCES_NAME, MODE_PRIVATE)
                preferences.edit()
                    .putString(KEY_DIAGNOSTIC_STATUS, "running")
                    .putString(KEY_DIAGNOSTIC_MESSAGE, "Sending one DNS A query for example.com through the configured upstream transport.")
                    .putString(KEY_DIAGNOSTIC_STARTED_AT, Instant.now().toString())
                    .putString(KEY_DIAGNOSTIC_NETWORK_START, networkAtStart.report)
                    .putString(KEY_DIAGNOSTIC_NETWORK_START_SIGNATURE, networkAtStart.fingerprint)
                    .remove(KEY_DIAGNOSTIC_COMPLETED_AT)
                    .remove(KEY_DIAGNOSTIC_NETWORK_END)
                    .remove(KEY_DIAGNOSTIC_NETWORK_END_SIGNATURE)
                    .putBoolean(KEY_DIAGNOSTIC_NETWORK_CHANGED, false)
                    .apply()
                sendDiagnosticResultBroadcast()

                val result = DnsRouteDiagnostic.run(transport)
                val networkAtEnd = DnsNetworkSnapshot.capture(this)
                val networkChanged = networkAtStart.fingerprint != networkAtEnd.fingerprint
                val resultStatus = when {
                    !result.validDnsResponse -> "failed"
                    result.resolved -> "success"
                    else -> "response_only"
                }
                preferences.edit()
                    .putString(KEY_DIAGNOSTIC_STATUS, resultStatus)
                    .putString(KEY_DIAGNOSTIC_MESSAGE, result.message)
                    .putString(KEY_DIAGNOSTIC_COMPLETED_AT, Instant.now().toString())
                    .putBoolean(KEY_DIAGNOSTIC_RESPONSE_RECEIVED, result.responseReceived)
                    .putBoolean(KEY_DIAGNOSTIC_VALID_RESPONSE, result.validDnsResponse)
                    .putBoolean(KEY_DIAGNOSTIC_RESOLVED, result.resolved)
                    .putLong(KEY_DIAGNOSTIC_LATENCY_MILLIS, result.elapsedMillis)
                    .putInt(KEY_DIAGNOSTIC_RESPONSE_CODE, result.responseCode ?: -1)
                    .putInt(KEY_DIAGNOSTIC_ANSWER_COUNT, result.answerCount ?: -1)
                    .putString(KEY_DIAGNOSTIC_NETWORK_END, networkAtEnd.report)
                    .putString(KEY_DIAGNOSTIC_NETWORK_END_SIGNATURE, networkAtEnd.fingerprint)
                    .putBoolean(KEY_DIAGNOSTIC_NETWORK_CHANGED, networkChanged)
                    .apply()
            } catch (exception: Exception) {
                Log.e(TAG, "DNS route diagnostic could not complete", exception)
                persistDiagnosticFailure(
                    "DNS route diagnostic could not complete (${exception.javaClass.simpleName})."
                )
            } finally {
                diagnosticRunning.set(false)
                sendDiagnosticResultBroadcast()
            }
        }, "PrivaCage-DNS-Diagnostic").apply {
            isDaemon = true
            start()
        }
    }

    private fun persistDiagnosticFailure(message: String) {
        getSharedPreferences(PREFERENCES_NAME, MODE_PRIVATE).edit()
            .putString(KEY_DIAGNOSTIC_STATUS, "failed")
            .putString(KEY_DIAGNOSTIC_MESSAGE, message)
            .putString(KEY_DIAGNOSTIC_COMPLETED_AT, Instant.now().toString())
            .putBoolean(KEY_DIAGNOSTIC_RESPONSE_RECEIVED, false)
            .putBoolean(KEY_DIAGNOSTIC_VALID_RESPONSE, false)
            .putBoolean(KEY_DIAGNOSTIC_RESOLVED, false)
            .putLong(KEY_DIAGNOSTIC_LATENCY_MILLIS, 0L)
            .putInt(KEY_DIAGNOSTIC_RESPONSE_CODE, -1)
            .putInt(KEY_DIAGNOSTIC_ANSWER_COUNT, -1)
            .remove(KEY_DIAGNOSTIC_NETWORK_START)
            .remove(KEY_DIAGNOSTIC_NETWORK_START_SIGNATURE)
            .remove(KEY_DIAGNOSTIC_NETWORK_END)
            .remove(KEY_DIAGNOSTIC_NETWORK_END_SIGNATURE)
            .putBoolean(KEY_DIAGNOSTIC_NETWORK_CHANGED, false)
            .apply()
    }

    private fun sendDiagnosticResultBroadcast() {
        sendBroadcast(Intent(ACTION_DIAGNOSTIC_RESULT).setPackage(packageName))
    }

    private fun publishState(state: String, message: String) {
        getSharedPreferences(PREFERENCES_NAME, MODE_PRIVATE).edit()
            .putString(VpnSessionStatus.KEY_STATE, state)
            .putString(VpnSessionStatus.KEY_MESSAGE, message)
            .putString(VpnSessionStatus.KEY_PROCESS_ID, PROCESS_SESSION_ID)
            .apply()
        sendBroadcast(Intent(ACTION_STATE_CHANGED).setPackage(packageName))
    }

    private fun persistStats(snapshot: DnsTunnelStatsSnapshot) {
        getSharedPreferences(PREFERENCES_NAME, MODE_PRIVATE).edit()
            .putLong(KEY_STATS_BLOCKED, snapshot.blockedQueries)
            .putLong(KEY_STATS_FORWARDED, snapshot.forwardedQueries)
            .putLong(KEY_STATS_UNSUPPORTED, snapshot.unsupportedOrMalformedPackets)
            .putLong(KEY_STATS_UPSTREAM_FAILURES, snapshot.upstreamFailures)
            .apply()
    }

    private fun startVpnForeground() {
        createNotificationChannel()
        val notification = buildNotification(
            "DNS filtering active",
            "Filtering configured domains using the resolver you selected.",
            ongoing = true
        )
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun postFailureNotification(message: String) {
        createNotificationChannel()
        getSystemService(NotificationManager::class.java).notify(
            NOTIFICATION_ID,
            buildNotification("DNS filtering stopped", message, ongoing = false)
        )
    }

    private fun buildNotification(title: String, message: String, ongoing: Boolean): Notification {
        val pendingIntent = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        return Notification.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentTitle(title)
            .setContentText(message)
            .setContentIntent(pendingIntent)
            .setOngoing(ongoing)
            .build()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            getSystemService(NotificationManager::class.java).createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "PrivaCage DNS filtering", NotificationManager.IMPORTANCE_LOW)
            )
        }
    }

    private fun stopVpn() {
        val hadTunnel = running || tunnel != null
        running = false
        diagnosticForwarder = null
        closeTunnel()
        stopForeground(STOP_FOREGROUND_REMOVE)
        if (hadTunnel) {
            publishState(VpnSessionStatus.STATE_STOPPED, "DNS filtering stopped.")
        }
    }

    @Synchronized
    private fun closeTunnel() {
        val active = tunnel
        tunnel = null
        try {
            active?.close()
        } catch (exception: IOException) {
            Log.w(TAG, "Error while closing VPN descriptor", exception)
        }
    }

    private fun isIpv4Address(value: String): Boolean {
        val parts = value.split('.')
        if (parts.size != 4) return false
        return parts.all { part ->
            part.isNotEmpty() && part.length <= 3 && part.all(Char::isDigit) &&
                (part.toIntOrNull()?.let { it in 0..255 } ?: false)
        }
    }

    companion object {
        const val PREFERENCES_NAME = "privacage_local_dns"
        const val KEY_RESOLVER_IP = "resolver_ipv4"
        const val KEY_DOT_ENABLED = "dns_over_tls_enabled"
        const val KEY_DOT_HOSTNAME = "dns_over_tls_hostname"
        const val KEY_BLOCKED_DOMAINS = "blocked_domains"
        const val KEY_STATS_BLOCKED = "dns_stats_blocked"
        const val KEY_STATS_FORWARDED = "dns_stats_forwarded"
        const val KEY_STATS_UNSUPPORTED = "dns_stats_unsupported"
        const val KEY_STATS_UPSTREAM_FAILURES = "dns_stats_upstream_failures"
        const val ACTION_START = "org.privacage.android.action.START_DNS_VPN"
        const val ACTION_STATE_CHANGED = "org.privacage.android.action.DNS_VPN_STATE_CHANGED"
        const val ACTION_RUN_DIAGNOSTIC = "org.privacage.android.action.RUN_DNS_DIAGNOSTIC"
        const val ACTION_DIAGNOSTIC_RESULT = "org.privacage.android.action.DNS_DIAGNOSTIC_RESULT"
        const val KEY_DIAGNOSTIC_STATUS = "dns_diagnostic_status"
        const val KEY_DIAGNOSTIC_MESSAGE = "dns_diagnostic_message"
        const val KEY_DIAGNOSTIC_STARTED_AT = "dns_diagnostic_started_at"
        const val KEY_DIAGNOSTIC_COMPLETED_AT = "dns_diagnostic_completed_at"
        const val KEY_DIAGNOSTIC_RESPONSE_RECEIVED = "dns_diagnostic_response_received"
        const val KEY_DIAGNOSTIC_VALID_RESPONSE = "dns_diagnostic_valid_response"
        const val KEY_DIAGNOSTIC_RESOLVED = "dns_diagnostic_resolved"
        const val KEY_DIAGNOSTIC_LATENCY_MILLIS = "dns_diagnostic_latency_ms"
        const val KEY_DIAGNOSTIC_RESPONSE_CODE = "dns_diagnostic_response_code"
        const val KEY_DIAGNOSTIC_ANSWER_COUNT = "dns_diagnostic_answer_count"
        const val KEY_DIAGNOSTIC_NETWORK_START = "dns_diagnostic_network_start"
        const val KEY_DIAGNOSTIC_NETWORK_START_SIGNATURE = "dns_diagnostic_network_start_signature"
        const val KEY_DIAGNOSTIC_NETWORK_END = "dns_diagnostic_network_end"
        const val KEY_DIAGNOSTIC_NETWORK_END_SIGNATURE = "dns_diagnostic_network_end_signature"
        const val KEY_DIAGNOSTIC_NETWORK_CHANGED = "dns_diagnostic_network_changed"
        internal val PROCESS_SESSION_ID: String = UUID.randomUUID().toString()
        private const val TAG = "PrivaCageDnsVpn"
        private const val CHANNEL_ID = "privacage_dns_filtering"
        private const val NOTIFICATION_ID = 4108
        private const val DNS_PORT = 53
        private const val MAX_IP_PACKET_SIZE = 65_535
        private const val STATS_FLUSH_PACKET_INTERVAL = 16
        private const val VPN_INTERFACE_ADDRESS = "10.111.0.1"
        private const val VIRTUAL_DNS_ADDRESS = "10.111.0.2"
        private const val VPN_IPV6_INTERFACE_ADDRESS = "fd42:1111:2222::1"
        private const val VIRTUAL_IPV6_DNS_ADDRESS = "fd42:1111:2222::2"
    }
}
