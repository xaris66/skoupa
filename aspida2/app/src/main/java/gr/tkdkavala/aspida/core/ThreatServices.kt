package gr.tkdkavala.aspida.core

import java.net.URLEncoder

/** Ελάχιστη διεπαφή HTTP ώστε ο πυρήνας να δοκιμάζεται χωρίς δίκτυο. */
interface Http {
    data class Response(val code: Int, val body: String, val location: String? = null)
    /** Αίτημα χωρίς αυτόματη ακολούθηση ανακατευθύνσεων. Πετάει IOException σε αποτυχία δικτύου. */
    fun request(method: String, url: String, headers: Map<String, String> = emptyMap(), form: Map<String, String>? = null, readBody: Boolean = true): Response
}

class ServiceUnavailable(msg: String) : Exception(msg)

/** Ένα αποτέλεσμα απειλής για συγκεκριμένο URL. */
data class ThreatHit(val url: String, val source: String, val types: List<String>)

/**
 * Google Safe Browsing v5 — urls:search (GET, έως 50 URLs, κενό σώμα).
 * Τηρεί το cacheDuration του διακομιστή, όπως απαιτούν οι όροι χρήσης.
 */
class SafeBrowsingV5(private val http: Http, private val apiKey: () -> String?, private val clock: Clock = SystemClock) {
    private data class Entry(val hits: List<ThreatHit>, val expires: Long)
    private val cache = HashMap<String, Entry>()

    val name = "Google Safe Browsing"

    fun check(urls: List<String>): List<ThreatHit> {
        val key = apiKey()?.trim().orEmpty()
        if (key.isEmpty()) throw ServiceUnavailable("Δεν έχει οριστεί κλειδί Google Safe Browsing")
        val now = clock.now()
        val todo = urls.distinct().filter { u -> cache[u]?.let { it.expires <= now } ?: true }.take(50)
        if (todo.isNotEmpty()) {
            val q = todo.joinToString("&") { "urls=" + URLEncoder.encode(it, "UTF-8") }
            val resp = try {
                http.request("GET", "https://safebrowsing.googleapis.com/v5/urls:search?$q&key=" + URLEncoder.encode(key, "UTF-8"))
            } catch (e: Exception) { throw ServiceUnavailable("Δεν υπάρχει σύνδεση με Google Safe Browsing") }
            if (resp.code != 200) throw ServiceUnavailable("Google Safe Browsing απάντησε με κωδικό ${resp.code}")
            val json = try { Json.parse(resp.body) as? Map<*, *> } catch (e: Exception) { null }
                ?: throw ServiceUnavailable("Άκυρη απάντηση Google Safe Browsing")
            val hits = (json["threats"] as? List<*>).orEmpty().mapNotNull { t ->
                val m = t as? Map<*, *> ?: return@mapNotNull null
                ThreatHit(m["url"] as? String ?: "", name, (m["threatTypes"] as? List<*>).orEmpty().map { it.toString() })
            }
            val dur = parseDuration(json["cacheDuration"] as? String)
            // Χωρίς ευρήματα επιτρέπεται επέκταση έως 24 ώρες· με ευρήματα τηρούμε ακριβώς τον διακομιστή.
            val ttl = if (hits.isEmpty()) maxOf(dur, 30 * 60_000L).coerceAtMost(24 * 3600_000L) else dur
            // Η λήξη ισχύει για ΟΛΑ τα URLs του αιτήματος.
            todo.forEach { u -> cache[u] = Entry(hits.filter { h -> covers(h.url, u) }, now + ttl) }
            // Ευρήματα για εκφράσεις (host/path prefix) που δεν ταιριάζουν ακριβώς: απόδοση σε όλα τα URLs με αυτό το πρόθεμα.
        }
        return urls.flatMap { cache[it]?.hits.orEmpty() }.distinct()
    }

    private fun covers(threatUrl: String, requested: String): Boolean {
        val t = threatUrl.removePrefix("https://").removePrefix("http://").trimEnd('/')
        val r = requested.removePrefix("https://").removePrefix("http://")
        if (t.isEmpty()) return false
        val tHost = t.substringBefore('/')
        val rHost = r.substringBefore('/')
        val hostOk = rHost == tHost || rHost.endsWith(".$tHost")
        val tPath = t.substringAfter('/', "")
        return hostOk && (tPath.isEmpty() || r.substringAfter('/', "").startsWith(tPath))
    }

    companion object {
        fun parseDuration(s: String?): Long {
            val v = s?.removeSuffix("s")?.toDoubleOrNull() ?: return 5 * 60_000L
            return (v * 1000).toLong().coerceAtLeast(0)
        }
    }
}

/** URLhaus (abuse.ch) — συμπληρωματικός έλεγχος για συνδέσμους που διανέμουν malware. */
class UrlHaus(private val http: Http, private val authKey: () -> String?) {
    val name = "URLhaus"
    fun check(url: String): ThreatHit? {
        val key = authKey()?.trim().orEmpty()
        if (key.isEmpty()) throw ServiceUnavailable("Δεν έχει οριστεί κλειδί URLhaus")
        val resp = try {
            http.request("POST", "https://urlhaus-api.abuse.ch/v1/url/", mapOf("Auth-Key" to key), mapOf("url" to url))
        } catch (e: Exception) { throw ServiceUnavailable("Δεν υπάρχει σύνδεση με URLhaus") }
        if (resp.code != 200) throw ServiceUnavailable("URLhaus απάντησε με κωδικό ${resp.code}")
        val json = try { Json.parse(resp.body) as? Map<*, *> } catch (e: Exception) { null }
            ?: throw ServiceUnavailable("Άκυρη απάντηση URLhaus")
        return when (json["query_status"]) {
            "ok" -> ThreatHit(url, name, listOf(json["threat"]?.toString() ?: "malware_download"))
            "no_results" -> null
            else -> throw ServiceUnavailable("URLhaus: ${json["query_status"]}")
        }
    }
}

/** Έλεγχος hash αρχείου στη MalwareBazaar (στέλνεται ΜΟΝΟ το SHA-256, ποτέ το αρχείο). */
class MalwareBazaar(private val http: Http, private val authKey: () -> String?) {
    val name = "MalwareBazaar"
    fun check(sha256: String): ThreatHit? {
        val key = authKey()?.trim().orEmpty()
        if (key.isEmpty()) throw ServiceUnavailable("Δεν έχει οριστεί κλειδί abuse.ch")
        val resp = try {
            http.request("POST", "https://mb-api.abuse.ch/api/v1/", mapOf("Auth-Key" to key), mapOf("query" to "get_info", "hash" to sha256))
        } catch (e: Exception) { throw ServiceUnavailable("Δεν υπάρχει σύνδεση με MalwareBazaar") }
        if (resp.code != 200) throw ServiceUnavailable("MalwareBazaar απάντησε με κωδικό ${resp.code}")
        val json = try { Json.parse(resp.body) as? Map<*, *> } catch (e: Exception) { null }
            ?: throw ServiceUnavailable("Άκυρη απάντηση MalwareBazaar")
        return when (json["query_status"]) {
            "ok" -> {
                val d = (json["data"] as? List<*>)?.firstOrNull() as? Map<*, *>
                ThreatHit(sha256, name, listOf(d?.get("signature")?.toString() ?: "known_malware"))
            }
            "hash_not_found", "no_results" -> null
            else -> throw ServiceUnavailable("MalwareBazaar: ${json["query_status"]}")
        }
    }
}
