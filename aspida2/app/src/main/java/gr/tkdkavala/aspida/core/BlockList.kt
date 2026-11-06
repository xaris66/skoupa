package gr.tkdkavala.aspida.core

import java.security.MessageDigest

/**
 * Προσωρινοί αποκλεισμοί (όχι μόνιμη καραντίνα).
 * - Μπαίνουν ΜΟΝΟ σε επιβεβαιωμένες απειλές (Safe Browsing / URLhaus), ποτέ από τοπικούς κανόνες.
 * - Αφορούν το συγκεκριμένο URL (όχι ολόκληρο κοινόχρηστο domain).
 * - Έχουν αιτιολογία, ημερομηνία λήξης και επανέλεγχο.
 * - Αποθηκεύεται hash του URL (ελαχιστοποίηση δεδομένων) + μόνο το όνομα host για εμφάνιση.
 */
class BlockList(private val clock: Clock = SystemClock) {
    data class Entry(
        val urlHash: String,
        val displayHost: String,
        val reason: String,
        val source: String,
        val createdAt: Long,
        val expiresAt: Long,
    )

    private val entries = LinkedHashMap<String, Entry>()

    fun all(): List<Entry> = entries.values.toList()

    fun add(url: String, host: String, reason: String, source: String, durationMs: Long = 7L * 24 * 3600_000): Entry {
        val now = clock.now()
        val e = Entry(hash(url), host, reason, source, now, now + durationMs)
        entries[e.urlHash] = e
        return e
    }

    /** Επιστρέφει ενεργό αποκλεισμό για ΑΚΡΙΒΩΣ αυτό το URL. Οι ληγμένοι επιστρέφονται ως null (θέλουν επανέλεγχο). */
    fun activeFor(url: String): Entry? {
        val e = entries[hash(url)] ?: return null
        return if (e.expiresAt > clock.now()) e else null
    }

    fun expired(): List<Entry> = entries.values.filter { it.expiresAt <= clock.now() }

    /** Αφαίρεση (η εφαρμογή ζητά πρώτα δακτυλικό/PIN). */
    fun remove(urlHash: String): Boolean = entries.remove(urlHash) != null

    /** Μετά από επανέλεγχο: αν δεν είναι πια απειλή, φεύγει· αλλιώς ανανεώνεται. */
    fun recheckDone(urlHash: String, stillDangerous: Boolean, durationMs: Long = 7L * 24 * 3600_000) {
        val e = entries[urlHash] ?: return
        if (!stillDangerous) entries.remove(urlHash)
        else entries[urlHash] = e.copy(expiresAt = clock.now() + durationMs)
    }

    fun restore(list: List<Entry>) { entries.clear(); list.forEach { entries[it.urlHash] = it } }

    companion object {
        fun hash(url: String): String = MessageDigest.getInstance("SHA-256").digest(url.toByteArray()).joinToString("") { "%02x".format(it) }
    }
}
