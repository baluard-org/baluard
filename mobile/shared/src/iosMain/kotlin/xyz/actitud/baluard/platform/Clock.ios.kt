package xyz.actitud.baluard.platform

/** iOS/Kotlin-Native epoch millis via kotlin.system. */
actual object Clock {
    actual fun currentTimeMillis(): Long = kotlin.system.getTimeMillis()
}
