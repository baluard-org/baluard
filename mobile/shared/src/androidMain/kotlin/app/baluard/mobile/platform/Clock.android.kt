package app.baluard.mobile.platform

/** Android/JVM epoch millis. */
actual object Clock {
    actual fun currentTimeMillis(): Long = System.currentTimeMillis()
}
