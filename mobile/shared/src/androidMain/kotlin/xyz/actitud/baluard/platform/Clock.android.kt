package xyz.actitud.baluard.platform

/** Android/JVM epoch millis. */
actual object Clock {
    actual fun currentTimeMillis(): Long = System.currentTimeMillis()
}
