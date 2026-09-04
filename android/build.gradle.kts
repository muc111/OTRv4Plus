plugins {
    id("com.android.application") version "8.7.3" apply false
    id("org.jetbrains.kotlin.android") version "2.0.21" apply false
    // Chaquopy embeds CPython. The Python requirement is 3.12+ (PEP 701
    // f-strings in otrv4+.py) -- see android_bridge/bootstrap.py.
    id("com.chaquo.python") version "16.0.0" apply false
}
