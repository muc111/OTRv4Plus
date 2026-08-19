# Chaquopy's runtime reaches Python objects reflectively; keep its surface.
-keep class com.chaquo.python.** { *; }

# The bridge's data classes cross into Python by attribute name.
-keep class org.otrv4plus.android.bridge.** { *; }

# Strip every log call from release builds. The bridge never logs sensitive
# values by construction, but an APK that cannot log them at all is a stronger
# guarantee than one that merely does not.
-assumenosideeffects class android.util.Log {
    public static *** v(...);
    public static *** d(...);
    public static *** i(...);
    public static *** w(...);
    public static *** e(...);
}
