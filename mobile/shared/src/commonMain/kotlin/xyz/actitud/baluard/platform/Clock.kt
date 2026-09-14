package xyz.actitud.baluard.platform

/**
 * Wall-clock milliseconds. Expect/actual because `System.currentTimeMillis()`
 * does not exist on Kotlin/Native; actuals read the platform clock.
 */
expect object Clock { fun currentTimeMillis(): Long }
