package xyz.actitud.baluard.platform

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.hardware.usb.UsbConstants
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbDeviceConnection
import android.hardware.usb.UsbEndpoint
import android.hardware.usb.UsbInterface
import android.hardware.usb.UsbManager
import android.nfc.NfcAdapter
import android.nfc.tech.IsoDep
import android.os.Build
import xyz.actitud.baluard.BaluardException
import xyz.actitud.baluard.MobileHardwareTransport
import xyz.actitud.baluard.MobileTransportProtocol
import java.util.concurrent.CountDownLatch
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

private const val YUBICO_VENDOR_ID = 0x1050
private const val TAG_WAIT_SECONDS = 20L
private const val USB_PERMISSION_WAIT_SECONDS = 60L

private fun crumb(message: String) {
    println("BaluardUsb[${Thread.currentThread().name}] $message")
}
private const val USB_IO_TIMEOUT_MS = 20_000

actual fun securityKeysSupported(): Boolean {
    val context = AppContextHolder.get() ?: return false
    return NfcAdapter.getDefaultAdapter(context) != null ||
        context.packageManager.hasSystemFeature(PackageManager.FEATURE_USB_HOST)
}

actual fun newSecurityKeyTransport(): MobileHardwareTransport {
    val context = AppContextHolder.require()
    val activity = AppContextHolder.activity()
        ?: throw BaluardException.Vault("Open Baluard before connecting the key")
    val usb = context.getSystemService(UsbManager::class.java)
        ?.deviceList?.values?.firstOrNull(::isFidoDevice)
    return if (usb != null) UsbSecurityKeyTransport(context, usb) else NfcSecurityKeyTransport(activity)
}

private fun fidoInterface(device: UsbDevice): UsbInterface? {
    for (i in 0 until device.interfaceCount) {
        val iface = device.getInterface(i)
        if (iface.interfaceClass != UsbConstants.USB_CLASS_HID ||
            iface.interfaceSubclass == UsbConstants.USB_INTERFACE_SUBCLASS_BOOT
        ) {
            continue
        }
        var input = false
        var output = false
        for (j in 0 until iface.endpointCount) {
            val endpoint = iface.getEndpoint(j)
            if (endpoint.maxPacketSize != 64) continue
            if (endpoint.direction == UsbConstants.USB_DIR_IN) input = true
            if (endpoint.direction == UsbConstants.USB_DIR_OUT) output = true
        }
        if (input && output) return iface
    }
    return null
}

private fun isFidoDevice(device: UsbDevice): Boolean =
    device.vendorId == YUBICO_VENDOR_ID && fidoInterface(device) != null

private class NfcSecurityKeyTransport(
    private val activity: androidx.fragment.app.FragmentActivity,
) : MobileHardwareTransport, NfcAdapter.ReaderCallback {
    private val adapter = NfcAdapter.getDefaultAdapter(activity)
        ?: throw BaluardException.Vault("This device has no NFC")
    private val tags = LinkedBlockingQueue<IsoDep>(1)
    private val readerStarted = AtomicBoolean(false)
    private val closed = AtomicBoolean(false)
    @Volatile private var connectedTag: IsoDep? = null
    @Volatile private var extendedApdu = false

    override fun protocol(): MobileTransportProtocol = MobileTransportProtocol.NFC
    override fun supportsExtendedApdu(): Boolean {
        awaitTag()
        return extendedApdu
    }

    private fun awaitTag(): IsoDep {
        if (closed.get()) throw BaluardException.Vault("Security key operation was cancelled")
        if (!adapter.isEnabled) throw BaluardException.Vault("Turn on NFC and retry")
        startReader()
        return connectedTag ?: run {
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(TAG_WAIT_SECONDS)
            while (!closed.get() && System.nanoTime() < deadline) {
                val discovered = try {
                    tags.poll(250, TimeUnit.MILLISECONDS)
                } catch (e: InterruptedException) {
                    Thread.currentThread().interrupt()
                    throw BaluardException.Vault("Security key wait cancelled")
                }
                if (discovered != null) {
                    connectedTag = discovered
                    return discovered
                }
            }
            if (closed.get()) throw BaluardException.Vault("Security key operation was cancelled")
            throw BaluardException.Vault("Hold the security key to the back of the phone")
        }
    }

    override fun transceive(request: ByteArray): ByteArray {
        val tag = awaitTag()
        return try {
            tag.transceive(request)
        } catch (e: Exception) {
            throw BaluardException.Vault("Security key connection lost. Hold it steady and retry")
        }
    }

    @Synchronized
    override fun onTagDiscovered(tag: android.nfc.Tag?) {
        if (closed.get() || connectedTag != null) return
        val iso = tag?.let(IsoDep::get) ?: return
        try {
            iso.connect()
            iso.timeout = 10_000
            extendedApdu = iso.isExtendedLengthApduSupported
            if (closed.get() || connectedTag != null || !tags.offer(iso)) {
                runCatching { iso.close() }
            }
        } catch (e: Exception) {
            runCatching { iso.close() }
        }
    }

    @Synchronized
    private fun startReader() {
        if (closed.get()) throw BaluardException.Vault("Security key operation was cancelled")
        if (!readerStarted.compareAndSet(false, true)) return
        try {
            adapter.enableReaderMode(
                activity,
                this,
                NfcAdapter.FLAG_READER_NFC_A or NfcAdapter.FLAG_READER_NFC_B or
                    NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK or NfcAdapter.FLAG_READER_NO_PLATFORM_SOUNDS,
                null,
            )
        } catch (e: Exception) {
            readerStarted.set(false)
            throw BaluardException.Vault("NFC could not start. Check NFC permission and retry")
        }
    }

    override fun write(report: ByteArray) = throw BaluardException.Vault("USB operation on NFC transport")
    override fun read(): ByteArray = throw BaluardException.Vault("USB operation on NFC transport")

    @Synchronized
    override fun shutdown() {
        if (!closed.compareAndSet(false, true)) return
        runCatching { connectedTag?.close() }
        runCatching { tags.poll()?.close() }
        connectedTag = null
        if (readerStarted.get()) runCatching {
            adapter.disableReaderMode(AppContextHolder.activity() ?: activity)
        }
    }
}

private class UsbSecurityKeyTransport(
    private val context: Context,
    private val device: UsbDevice,
) : MobileHardwareTransport {
    private val manager = context.getSystemService(UsbManager::class.java)
    private var connection: UsbDeviceConnection? = null
    private var usbInterface: UsbInterface? = null
    private var input: UsbEndpoint? = null
    private var output: UsbEndpoint? = null
    private var permission: CountDownLatch? = null
    private var receiverRegistered = false
    @Volatile private var permissionGranted = false
    private val closed = AtomicBoolean(false)

    private val receiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            val grantedDevice = if (Build.VERSION.SDK_INT >= 33) {
                intent?.getParcelableExtra(UsbManager.EXTRA_DEVICE, UsbDevice::class.java)
            } else {
                @Suppress("DEPRECATION") intent?.getParcelableExtra(UsbManager.EXTRA_DEVICE)
            }
            if (grantedDevice == device) {
                permissionGranted = intent?.getBooleanExtra(UsbManager.EXTRA_PERMISSION_GRANTED, false) == true
            }
            crumb("permission result granted=$permissionGranted")
            permission?.countDown()
        }
    }

    override fun protocol(): MobileTransportProtocol = MobileTransportProtocol.USB
    override fun supportsExtendedApdu(): Boolean = false

    private fun unregisterPermissionReceiver() {
        if (!receiverRegistered) return
        runCatching { context.unregisterReceiver(receiver) }
        receiverRegistered = false
    }

    private fun requestPermission() {
        permissionGranted = false
        permission = CountDownLatch(1)
        val filter = IntentFilter(ACTION_USB_PERMISSION)
        if (Build.VERSION.SDK_INT >= 33) {
            context.registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("DEPRECATION") context.registerReceiver(receiver, filter)
        }
        receiverRegistered = true
        try {
            val intent = PendingIntent.getBroadcast(
                context,
                device.deviceId,
                Intent(ACTION_USB_PERMISSION).setPackage(context.packageName),
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE,
            )
            manager.requestPermission(device, intent)
            val granted = try {
                permission?.await(USB_PERMISSION_WAIT_SECONDS, TimeUnit.SECONDS) == true && permissionGranted
            } catch (e: InterruptedException) {
                Thread.currentThread().interrupt()
                false
            } || manager.hasPermission(device)
            crumb("permission wait done granted=$granted")
            if (!granted) throw BaluardException.Vault("USB permission was not granted")
        } finally {
            unregisterPermissionReceiver()
        }
    }

    private fun open() {
        if (closed.get()) throw BaluardException.Vault("Security key operation was cancelled")
        if (connection != null) return
        crumb("open hasPermission=${manager.hasPermission(device)}")
        if (!manager.hasPermission(device)) requestPermission()
        val iface = fidoInterface(device)
            ?: throw BaluardException.Vault("No CTAPHID interface on the USB key")
        val conn = try {
            manager.openDevice(device)
        } catch (e: Exception) {
            crumb("openDevice threw: $e")
            throw BaluardException.Vault("Could not open the USB key")
        } ?: run {
            crumb("openDevice returned null")
            throw BaluardException.Vault("Could not open the USB key")
        }
        try {
            val claimed = conn.claimInterface(iface, true)
            crumb("claim iface=${iface.id} ok=$claimed")
            if (!claimed) {
                throw BaluardException.Vault("Could not claim the USB key")
            }
            var inp: UsbEndpoint? = null
            var outp: UsbEndpoint? = null
            for (i in 0 until iface.endpointCount) {
                val endpoint = iface.getEndpoint(i)
                if (endpoint.maxPacketSize != 64) continue
                if (endpoint.direction == UsbConstants.USB_DIR_IN) inp = endpoint
                if (endpoint.direction == UsbConstants.USB_DIR_OUT) outp = endpoint
            }
            if (inp == null || outp == null) {
                throw BaluardException.Vault("The USB key has no CTAPHID endpoints")
            }
            usbInterface = iface
            connection = conn
            input = inp
            output = outp
        } catch (e: Exception) {
            runCatching { conn.releaseInterface(iface) }
            runCatching { conn.close() }
            throw e
        }
    }

    override fun write(report: ByteArray) {
        open()
        val conn = connection ?: throw BaluardException.Vault("USB key is not open")
        val bytes = if (report.size == 65) report.copyOfRange(1, 65) else report
        if (bytes.size != 64) throw BaluardException.Vault("Invalid CTAPHID report size")
        val sent = conn.bulkTransfer(output, bytes, bytes.size, USB_IO_TIMEOUT_MS)
        crumb("out ${bytes.size} -> sent=$sent")
        if (sent != bytes.size) throw BaluardException.Vault("USB key write failed")
    }

    override fun read(): ByteArray {
        open()
        val conn = connection ?: throw BaluardException.Vault("USB key is not open")
        val bytes = ByteArray(64)
        val received = conn.bulkTransfer(input, bytes, bytes.size, USB_IO_TIMEOUT_MS)
        crumb("in -> received=$received")
        if (received != 64) throw BaluardException.Vault("USB key read timed out")
        return byteArrayOf(0) + bytes
    }

    override fun transceive(request: ByteArray) = throw BaluardException.Vault("NFC operation on USB transport")

    override fun shutdown() {
        crumb("shutdown connection=${connection != null} stack=${Throwable().stackTraceToString().take(1200)}")
        if (!closed.compareAndSet(false, true)) return
        runCatching { permission?.countDown() }
        runCatching { unregisterPermissionReceiver() }
        runCatching { usbInterface?.let { connection?.releaseInterface(it) } }
        runCatching { connection?.close() }
        connection = null
    }

    private companion object {
        const val ACTION_USB_PERMISSION = "xyz.actitud.baluard.USB_PERMISSION"
    }
}
