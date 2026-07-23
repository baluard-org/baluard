package xyz.actitud.baluard.totp

/** Android/JVM epoch millis. */
actual object Clock {
    actual fun currentTimeMillis(): Long = System.currentTimeMillis()
}
