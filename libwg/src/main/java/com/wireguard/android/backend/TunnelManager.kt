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
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.Observer
import androidx.lifecycle.ProcessLifecycleOwner
import com.wireguard.config.Config
import com.wireguard.crypto.Key
import com.wireguard.crypto.KeyFormatException
import java.util.HashMap

class TunnelManager {

    val backend: VpnServiceBackend
    val builderProvider: VpnBuilderProvider
    val context: Context
    var currentTunnel: Tunnel? = null

    companion object {
        private val vpnService = MutableLiveData<VpnService>()
    }

    interface VpnBuilderProvider {
        fun patchBuilder(builder: android.net.VpnService.Builder): android.net.VpnService.Builder
    }

    init {

    }

    constructor(context: Context, builderProvider: VpnBuilderProvider) {
        this.backend = VpnServiceBackend(object: VpnServiceBackend.VpnServiceDelegate{
            override fun protect(socket: Int): Boolean {
                return vpnService.value?.protect(socket) ?: false
            }
        })
        this.context = context.applicationContext
        this.builderProvider = builderProvider
    }

    fun tunnelDown() {
        vpnService.value = null
    }

    fun tunnelUp(tunnel: Tunnel) {
        currentTunnel = tunnel
        val config = tunnel.config

        vpnService.observe(ProcessLifecycleOwner.get(), object: Observer<VpnService>{
            override fun onChanged(service: VpnService?) {
                if(service == null){
                    vpnService.removeObserver(this)
                    currentTunnel?.apply { backend.tunnelDown(this) }
                    return
                }

                val builder = service.Builder()
                builderProvider.patchBuilder(builder)
                builder.applyConfig(config)
                val tun = builder.establish() ?: return

                backend.tunnelUp(tunnel, tun, config.toWgUserspaceString())
            }
        })
        context.startService(Intent(context, VpnService::class.java))
    }

    fun isGranted(): Boolean {
        return prepare(context) == null
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

    public class VpnService : android.net.VpnService() {
        val builder: Builder
            get() {
                return Builder()
            }

        override fun onCreate() {
            super.onCreate()
            vpnService.value = this
        }

        override fun onDestroy() {
            vpnService.value = null
            super.onDestroy()
        }

        override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
            return super.onStartCommand(intent, flags, startId)
        }
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