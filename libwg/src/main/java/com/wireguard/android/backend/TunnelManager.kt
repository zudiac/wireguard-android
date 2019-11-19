/*
 * Copyright © 2019 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.wireguard.android.backend

import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.net.VpnService.prepare
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.Observer
import androidx.lifecycle.ProcessLifecycleOwner
import com.wireguard.config.Config

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