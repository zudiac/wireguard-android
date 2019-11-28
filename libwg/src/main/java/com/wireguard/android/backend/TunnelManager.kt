/*
 * Copyright © 2019 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.wireguard.android.backend

import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.net.VpnService.prepare
import android.os.SystemClock
import android.util.Pair
import com.wireguard.config.Config
import com.wireguard.crypto.Key
import com.wireguard.crypto.KeyFormatException
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import java.util.*

class TunnelManager(
    context: Context,
    private val builderProvider: VpnBuilderProvider
) {

    private val appContext = context.applicationContext
    private val backend: VpnServiceBackend = VpnServiceBackend(object: VpnServiceBackend.VpnServiceDelegate{
        override fun protect(socket: Int): Boolean {
            return currentService?.protect(socket) ?: false
        }
    })

    var currentTunnel: Tunnel? = null
    var currentService: VpnService? = null

    private var upTime = 0L
    val upDuration: Long
        get() {
            return if (isConnected()) {
                SystemClock.elapsedRealtime() - upTime
            } else {
                0L
            }
        }

    interface VpnBuilderProvider {
        fun patchBuilder(builder: android.net.VpnService.Builder): android.net.VpnService.Builder
    }

    fun tunnelDown() {
        currentTunnel?.let { backend.tunnelDown(it) }
        currentService = null
        upTime = 0L
    }

    fun tunnelUp(tunnel: Tunnel) {
        currentTunnel = tunnel
        val config = tunnel.config

        GlobalScope.launch(Dispatchers.Main) {
            currentService = serviceChannel.receive()
            currentService?.Builder()?.apply {
                builderProvider.patchBuilder(this)
                applyConfig(config)
                establish()?.let { fd ->
                    backend.tunnelUp(tunnel, fd, config.toWgUserspaceString())
                    if (upTime == 0L) {
                        upTime = SystemClock.elapsedRealtime()
                    }
                }
            }
        }

        appContext.startService(Intent(appContext, VpnService::class.java).apply {
            putExtra(VpnService.EXTRA_COMMAND, VpnService.COMMAND_TURN_ON)
        })
    }

    fun isGranted(): Boolean {
        return prepare(appContext) == null
    }

    fun isConnected(): Boolean {
        return currentTunnel?.state == Tunnel.State.Up
    }

    fun getConfig(tunnel: Tunnel): String? {
        return backend.getConfig(tunnel)
    }

    fun getStatistics(tunnel: Tunnel): Statistics {
        val stats = Statistics()
        if (tunnel !== currentTunnel) {
            return stats
        }
        val config = backend.getConfig(tunnel) ?: return stats
        var key: Key? = null
        var rx: Long = 0
        var tx: Long = 0
        for (line in config.split("\\n".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()) {
            if (line.startsWith("public_key=")) {
                key?.let { stats.add(it, rx, tx) }
                rx = 0
                tx = 0
                key = try {
                    Key.fromHex(line.substring(11))
                } catch (ignored: KeyFormatException) {
                    null
                }

            } else if (line.startsWith("rx_bytes=")) {
                if (key == null)
                    continue
                rx = try {
                    java.lang.Long.parseLong(line.substring(9))
                } catch (ignored: NumberFormatException) {
                    0
                }

            } else if (line.startsWith("tx_bytes=")) {
                if (key == null)
                    continue
                tx = try {
                    java.lang.Long.parseLong(line.substring(9))
                } catch (ignored: NumberFormatException) {
                    0
                }

            }
        }
        key?.let { stats.add(it, rx, tx) }
        return stats
    }

    class VpnService : android.net.VpnService() {
        private val serviceJob = Job()
        private val serviceScope = CoroutineScope(Dispatchers.Main + serviceJob)

        override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {

            when (intent?.getStringExtra(EXTRA_COMMAND) ?: "") {
                COMMAND_TURN_ON -> turnOn()
            }

            return super.onStartCommand(intent, flags, startId)
        }

        override fun onDestroy() {
            serviceJob.cancel()
            super.onDestroy()
        }

        private fun turnOn() = serviceScope.launch(Dispatchers.Main) {
            serviceChannel.send(this@VpnService)
        }

        companion object {
            const val EXTRA_COMMAND = "command"
            const val COMMAND_TURN_ON = "turn_on"
        }
    }

    companion object {
        private val serviceChannel = Channel<VpnService>()
    }
}

fun VpnService.Builder.applyConfig(config: Config){
    for (excludedApplication in config.getInterface().excludedApplications)
        addDisallowedApplication(excludedApplication)

    for (addr in config.getInterface().addresses)
        addAddress(addr.address, addr.mask)

    for (addr in config.getInterface().dnsServers)
        addDnsServer(addr.hostAddress)

    for (peer in config.peers) {
        for (addr in peer.allowedIps)
            addRoute(addr.address, addr.mask)
    }

    setMtu(config.getInterface().mtu.orElse(1280))

    setBlocking(true)
}

class Statistics {
    private var lastTouched = SystemClock.elapsedRealtime()
    private val peerBytes = HashMap<Key, Pair<Long, Long>>()

    private val isStale: Boolean
        get() = SystemClock.elapsedRealtime() - lastTouched > 900

    fun add(key: Key, rx: Long, tx: Long) {
        peerBytes[key] = Pair.create(rx, tx)
        lastTouched = SystemClock.elapsedRealtime()
    }

    fun peers(): Array<Key> {
        return peerBytes.keys.toTypedArray()
    }

    fun peerRx(peer: Key): Long {
        return if (!peerBytes.containsKey(peer)) 0 else peerBytes[peer]?.first ?: 0
    }

    fun peerTx(peer: Key): Long {
        return if (!peerBytes.containsKey(peer)) 0 else peerBytes[peer]?.second ?: 0
    }

    fun totalRx(): Long {
        var rx: Long = 0
        for (`val` in peerBytes.values) {
            rx += `val`.first
        }
        return rx
    }

    fun totalTx(): Long {
        var tx: Long = 0
        for (`val` in peerBytes.values) {
            tx += `val`.second
        }
        return tx
    }
}