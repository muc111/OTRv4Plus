package org.otrv4plus.android

import android.app.Application
import com.chaquo.python.Python
import com.chaquo.python.android.AndroidPlatform

/**
 * Starts the embedded CPython runtime once per process.
 *
 * Interpreter start-up is the cold-start cost of embedding Python. It is done
 * here, before any screen is drawn, so that in the finished product it happens
 * behind the unlock screen where the user does not perceive it.
 */
class OtrApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        if (!Python.isStarted()) {
            Python.start(AndroidPlatform(this))
        }
    }
}
