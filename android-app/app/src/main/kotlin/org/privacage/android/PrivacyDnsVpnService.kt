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
import java.util.UUID

class PrivacyDnsVpnService : VpnService() {
    @Volatile private var running = false
    @Volatile private var tunnel: ParcelFileDescriptor? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
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
            val resolver = InetSocketAddress(InetAddress.getByName(resolverText), DNS_PORT)
            val forwarder: DnsUpstreamTransport = if (prefs.getBoolean(KEY_DOT_ENABLED, false)) {
                val hostname = prefs.getString(KEY_DOT_HOSTNAME, "").orEmpty()
                require(hostname.isNotBlank()) { "DNS-over-TLS requires a certificate hostname" }
                DnsOverTlsForwarder(
                    resolverAddress = InetAddress.getByName(resolverText),
                    tlsHostname = hostname,
                    socketProtector = TcpSocketProtector { socket: Socket -> protect(socket) },
                    policyEngine = policy
                )
            } else {
                UdpDnsForwarder(
                    resolver,
                    UdpSocketProtector { socket: DatagramSocket -> protect(socket) },
                    policy,
                    tcpSocketProtector = TcpSocketProtector { socket: Socket -> protect(socket) }
                )
            }
            val engine = DnsTunnelEngine(DnsPacketProcessor(policy), forwarder)
            val descriptor = Builder()
                .setSession("PrivaCage DNS filtering")
                .setMtu(1500)
                .addAddress(VPN_INTERFACE_ADDRESS, 32)
                .addDnsServer(VIRTUAL_DNS_ADDRESS)
                .addRoute(VIRTUAL_DNS_ADDRESS, 32)
                .setBlocking(true)
                .establish() ?: throw IOException("Android refused to establish the VPN interface")

            tunnel = descriptor
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
                    engine.processIpv4Packet(packet)
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
                            LocalDnsEventHistory.record(this, packet, result.domain, result.action.name)
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
        internal val PROCESS_SESSION_ID: String = UUID.randomUUID().toString()
        private const val TAG = "PrivaCageDnsVpn"
        private const val CHANNEL_ID = "privacage_dns_filtering"
        private const val NOTIFICATION_ID = 4108
        private const val DNS_PORT = 53
        private const val MAX_IP_PACKET_SIZE = 65_535
        private const val STATS_FLUSH_PACKET_INTERVAL = 16
        private const val VPN_INTERFACE_ADDRESS = "10.111.0.1"
        private const val VIRTUAL_DNS_ADDRESS = "10.111.0.2"
    }
}
