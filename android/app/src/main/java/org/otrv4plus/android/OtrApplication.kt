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
        // The PDF renderer's isolated process (ui/PdfRenderService.kt) may
        // read no app files, so Python cannot start there, and is not needed.
        if (isolatedProcess()) return
        if (!Python.isStarted()) {
            Python.start(AndroidPlatform(this))
        }
    }

    companion object {
        /** Whether this process is an isolated one. Isolated UIDs are 99000-99999. */
        fun isolatedProcess(): Boolean =
            if (android.os.Build.VERSION.SDK_INT >= 28) android.os.Process.isIsolated()
            else android.os.Process.myUid() % 100_000 in 99_000..99_999
    }
}
