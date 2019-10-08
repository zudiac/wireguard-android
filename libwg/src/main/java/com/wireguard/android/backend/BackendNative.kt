/*
 * Copyright © 2019 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.wireguard.android.backend

open class BackendNative {

    external fun wgGetConfig(handle: Int): String

    external fun wgGetSocketV4(handle: Int): Int

    external fun wgGetSocketV6(handle: Int): Int

    external fun wgTurnOff(handle: Int)

    external fun wgTurnOn(ifName: String, tunFd: Int, settings: String): Int

    external fun wgVersion(): String

    init {
        System.loadLibrary("wg-go")
    }

}