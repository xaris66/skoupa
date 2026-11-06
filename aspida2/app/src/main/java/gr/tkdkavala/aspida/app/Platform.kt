package gr.tkdkavala.aspida.app

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import gr.tkdkavala.aspida.core.*
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder
import java.security.KeyStore
import java.util.concurrent.Executors
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** HTTP με όρια: χωρίς αυτόματες ανακατευθύνσεις, χωρίς cookies, σύντομα timeouts, μέγιστο σώμα 1 MB. */
class AndroidHttp : Http {
    override fun request(method: String, url: String, headers: Map<String, String>, form: Map<String, String>?, readBody: Boolean): Http.Response {
        val c = URL(url).openConnection() as HttpURLConnection
        try {
            c.instanceFollowRedirects = false
            c.connectTimeout = 6000; c.readTimeout = 8000
            c.useCaches = false
            c.requestMethod = method
            c.setRequestProperty("User-Agent", "Aspida/2.0 (Android; personal security)")
            c.setRequestProperty("Accept", "*/*")
            headers.forEach { (k, v) -> c.setRequestProperty(k, v) }
            if (form != null) {
                c.doOutput = true
                c.setRequestProperty("Content-Type", "application/x-www-form-urlencoded")
                val body = form.entries.joinToString("&") { URLEncoder.encode(it.key, "UTF-8") + "=" + URLEncoder.encode(it.value, "UTF-8") }
                c.outputStream.use { it.write(body.toByteArray()) }
            }
            val code = c.responseCode
            val loc = c.getHeaderField("Location")
            val text = if (!readBody || method == "HEAD") "" else {
                val s = if (code >= 400) c.errorStream else c.inputStream
                s?.use { ins ->
                    val out = java.io.ByteArrayOutputStream(); val b = ByteArray(8192); var tot = 0
                    while (true) { val r = ins.read(b); if (r < 0 || tot > 1_000_000) break; out.write(b, 0, r); tot += r }
                    out.toString("UTF-8")
                } ?: ""
            }
            return Http.Response(code, text, loc)
        } catch (e: IOException) { throw e } finally { c.disconnect() }
    }
}

/** Κρυπτογράφηση AES-256-GCM με κλειδί που δεν φεύγει ποτέ από το Android Keystore. */
object Crypto {
    private const val ALIAS = "aspida2_master"
    private fun key(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        val g = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        g.init(KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256).build())
        return g.generateKey()
    }
    fun encrypt(plain: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding"); c.init(Cipher.ENCRYPT_MODE, key())
        return c.iv + c.doFinal(plain)
    }
    fun decrypt(data: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, data.copyOfRange(0, 12)))
        return c.doFinal(data, 12, data.size - 12)
    }
}

/** Κρυπτογραφημένα αρχεία JSON στον ιδιωτικό χώρο της εφαρμογής. */
class SecureJsonFile(private val file: File) {
    @Synchronized fun read(): JSONObject = try {
        if (!file.exists()) JSONObject() else JSONObject(String(Crypto.decrypt(file.readBytes()), Charsets.UTF_8))
    } catch (e: Exception) { JSONObject() }
    @Synchronized fun write(o: JSONObject) {
        val tmp = File(file.path + ".tmp"); tmp.writeBytes(Crypto.encrypt(o.toString().toByteArray(Charsets.UTF_8))); tmp.renameTo(file)
    }
}

class Settings(private val f: SecureJsonFile) {
    private fun get() = f.read()
    private fun set(k: String, v: Any?) { val o = get(); if (v == null) o.remove(k) else o.put(k, v); f.write(o) }
    var safeBrowsingKey: String? get() = get().optString("gsb", "").ifEmpty { null }; set(v) = set("gsb", v?.trim())
    var abuseChKey: String? get() = get().optString("abuse", "").ifEmpty { null }; set(v) = set("abuse", v?.trim())
    var browserPackage: String? get() = get().optString("browser", "").ifEmpty { null }; set(v) = set("browser", v)
    var followRedirects: Boolean get() = get().optBoolean("redirects", true); set(v) = set("redirects", v)
    /** Τι γίνεται όταν δεν ολοκληρώνεται ο έλεγχος: true = ερώτηση, false = άνοιγμα με ειδοποίηση. */
    var askWhenUnchecked: Boolean get() = get().optBoolean("askUnchecked", true); set(v) = set("askUnchecked", v)
    var downloadsTree: String? get() = get().optString("tree", "").ifEmpty { null }; set(v) = set("tree", v)
    var backgroundScan: Boolean get() = get().optBoolean("bg", true); set(v) = set("bg", v)
    var lastBgScan: Long get() = get().optLong("lastBg", 0); set(v) = set("lastBg", v)
    var setupDone: Boolean get() = get().optBoolean("setup", false); set(v) = set("setup", v)
}

/** Ιστορικό με ελαχιστοποίηση: μόνο host/όνομα αρχείου, όχι πλήρες URL με παραμέτρους. */
class History(private val f: SecureJsonFile) {
    data class Item(val time: Long, val kind: String, val subject: String, val verdict: Verdict, val note: String)
    fun add(kind: String, subject: String, verdict: Verdict, note: String) {
        val o = f.read(); val a = o.optJSONArray("items") ?: JSONArray()
        val n = JSONArray().put(JSONObject().put("t", System.currentTimeMillis()).put("k", kind).put("s", subject.take(120)).put("v", verdict.name).put("n", note.take(200)))
        for (i in 0 until minOf(a.length(), 299)) n.put(a.get(i))
        f.write(o.put("items", n))
    }
    fun all(): List<Item> {
        val a = f.read().optJSONArray("items") ?: return emptyList()
        return (0 until a.length()).map { a.getJSONObject(it) }.map { Item(it.getLong("t"), it.getString("k"), it.getString("s"), runCatching { Verdict.valueOf(it.getString("v")) }.getOrDefault(Verdict.UNCHECKED), it.optString("n")) }
    }
    fun clear() = f.write(JSONObject())
}

class AspidaApp : Application() {
    lateinit var settings: Settings; private set
    lateinit var history: History; private set
    /** Η λίστα PSL φορτώνει στο παρασκήνιο ώστε η εφαρμογή να ανοίγει αμέσως. */
    val analyzer: UrlAnalyzer by lazy { UrlAnalyzer(PublicSuffixList(assets.open("public_suffix_list.dat").bufferedReader().readText())) }
    val blockList = BlockList()
    private lateinit var blockFile: SecureJsonFile
    val http = AndroidHttp()
    val io = Executors.newFixedThreadPool(3)
    lateinit var safeBrowsing: SafeBrowsingV5; private set

    override fun onCreate() {
        super.onCreate()
        instance = this
        settings = Settings(SecureJsonFile(File(filesDir, "settings.enc")))
        history = History(SecureJsonFile(File(filesDir, "history.enc")))
        blockFile = SecureJsonFile(File(filesDir, "blocks.enc"))
        loadBlocks()
        io.execute { analyzer }
        safeBrowsing = SafeBrowsingV5(http, { settings.safeBrowsingKey })
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel(CH_ALERTS, "Προειδοποιήσεις Ασπίδας", NotificationManager.IMPORTANCE_HIGH))
        ScanJobService.schedule(this)
    }

    fun linkChecker() = LinkChecker(analyzer, http, safeBrowsing,
        settings.abuseChKey?.let { k -> UrlHaus(http) { k } }, { settings.followRedirects })

    fun fileScanner() = FileScanner(hashLookup = settings.abuseChKey?.let { k -> MalwareBazaar(http) { k } })

    @Synchronized fun saveBlocks() {
        val a = JSONArray()
        blockList.all().forEach { a.put(JSONObject().put("h", it.urlHash).put("host", it.displayHost).put("r", it.reason).put("s", it.source).put("c", it.createdAt).put("e", it.expiresAt)) }
        blockFile.write(JSONObject().put("b", a))
    }
    private fun loadBlocks() {
        val a = blockFile.read().optJSONArray("b") ?: return
        blockList.restore((0 until a.length()).map { a.getJSONObject(it) }.map {
            BlockList.Entry(it.getString("h"), it.getString("host"), it.getString("r"), it.getString("s"), it.getLong("c"), it.getLong("e"))
        })
    }

    val quarantineDir: File get() = File(filesDir, "quarantine").apply { mkdirs() }

    companion object {
        const val CH_ALERTS = "alerts"
        lateinit var instance: AspidaApp
        fun of(c: Context) = c.applicationContext as AspidaApp
    }
}

fun b64(s: String): String = Base64.encodeToString(s.toByteArray(), Base64.NO_WRAP or Base64.URL_SAFE)
