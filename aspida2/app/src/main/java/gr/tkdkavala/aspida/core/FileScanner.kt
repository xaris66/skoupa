package gr.tkdkavala.aspida.core

import java.io.BufferedInputStream
import java.io.InputStream
import java.security.MessageDigest
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream

/**
 * Έλεγχος αρχείου χωρίς εκτέλεση: τύπος από το περιεχόμενο, SHA-256, γνωστές υπογραφές,
 * ύποπτες δομές, ασφαλής ανάλυση ZIP με όρια πόρων. Δεν διαγράφει ποτέ τίποτα.
 */
class FileScanner(
    private val knownBadHashes: Set<String> = setOf(EICAR_SHA256),
    private val hashLookup: MalwareBazaar? = null,
    private val limits: Limits = Limits(),
) {
    data class Limits(
        val maxBytesHashed: Long = 2L * 1024 * 1024 * 1024,
        val maxZipEntries: Int = 5000,
        val maxZipTotalUncompressed: Long = 512L * 1024 * 1024,
        val maxZipRatio: Double = 200.0,
        val maxZipDepth: Int = 2,
        val pdfScanBytes: Int = 8 * 1024 * 1024,
    )

    companion object {
        /** SHA-256 του επίσημου αβλαβούς αρχείου δοκιμής EICAR (68 bytes). */
        const val EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        const val EICAR_MARK = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
        private val executableExt = setOf("apk", "xapk", "apks", "exe", "dll", "scr", "bat", "cmd", "com", "msi", "js", "jse", "vbs", "vbe", "ps1", "jar", "sh", "elf", "dex", "hta", "lnk")
        private val docLikeExt = setOf("pdf", "jpg", "jpeg", "png", "gif", "webp", "heic", "doc", "docx", "xls", "xlsx", "txt", "mp4", "mp3")
    }

    /** `open` πρέπει να επιστρέφει ΝΕΟ stream σε κάθε κλήση (το αρχείο διαβάζεται έως 2 φορές). */
    fun scan(name: String, size: Long, open: () -> InputStream): FileResult {
        val findings = ArrayList<Finding>()
        val head = ByteArray(4096)
        val headLen = open().use { readFully(it, head) }
        val type = detectType(head, headLen, open)

        val sha = open().use { sha256(it, limits.maxBytesHashed) }

        // 1) Γνωστές υπογραφές
        if (sha in knownBadHashes) findings += Finding("hash", if (sha == EICAR_SHA256) "Αρχείο δοκιμής EICAR (αβλαβές, αναγνωρίζεται ως «ιός» δοκιμής)." else "Γνωστό κακόβουλο αρχείο (SHA-256).", confirmed = true, weight = 100)
        else if (headLen in 68..200 && String(head, 0, headLen, Charsets.ISO_8859_1).contains(EICAR_MARK))
            findings += Finding("eicar", "Περιέχει την υπογραφή δοκιμής EICAR.", confirmed = true, weight = 100)

        // 2) Παραπλανητικό όνομα / επέκταση
        val cleanName = name.replace(Regex("[\\u202A-\\u202E\\u2066-\\u2069]"), "")
        if (cleanName != name) findings += Finding("rtlo", "Το όνομα κρύβει χαρακτήρες αντιστροφής κειμένου — το πραγματικό όνομα είναι «$cleanName».", weight = 85)
        val parts = cleanName.lowercase().split('.')
        val ext = if (parts.size > 1) parts.last() else ""
        if (parts.size > 2 && parts[parts.size - 2] in docLikeExt && ext in executableExt)
            findings += Finding("double-ext", "Διπλή επέκταση «.${parts[parts.size - 2]}.$ext» — μοιάζει με έγγραφο/φωτογραφία αλλά είναι εκτελέσιμο.", weight = 85)
        val expected = expectedTypeForExt(ext)
        if (expected != null && type != "unknown" && type != expected && !(expected == "zip" && type in setOf("apk", "office"))) {
            val execType = type in setOf("apk", "dex", "elf", "pe", "script")
            findings += Finding("ext-mismatch", "Η επέκταση λέει «.$ext» αλλά το περιεχόμενο είναι ${typeTitle(type)}.", weight = if (execType) 85 else 45)
        }

        // 3) Δομή ανά τύπο
        when (type) {
            "pdf" -> scanPdf(open, findings)
            "zip", "apk", "office" -> open().use { scanZip(it, size, 0, findings, type) }
            "pe", "elf" -> findings += Finding("native-exec", "Εκτελέσιμο πρόγραμμα ${typeTitle(type)} — δεν τρέχει σε Android και συνήθως δεν έχει λόγο να βρίσκεται στο κινητό.", weight = 40)
            "script" -> findings += Finding("script", "Αρχείο εντολών (script). Μην το ανοίξεις αν δεν ξέρεις από πού ήρθε.", weight = 30)
        }
        if (type == "apk") findings += Finding("apk", "Αρχείο εγκατάστασης εφαρμογής (APK). Εγκατάστησε μόνο από πηγή που εμπιστεύεσαι.", weight = 20)

        // 4) Προαιρετικός έλεγχος hash (στέλνεται μόνο το SHA-256)
        if (hashLookup != null && findings.none { it.confirmed }) {
            try { hashLookup.check(sha)?.let { findings += Finding("mb", "MalwareBazaar: γνωστό κακόβουλο (${it.types.joinToString()}).", confirmed = true, weight = 100) } }
            catch (e: ServiceUnavailable) { findings += Finding("mb-fail", "Ο online έλεγχος υπογραφής δεν ολοκληρώθηκε: ${e.message}", weight = 0) }
        }

        val confirmed = findings.any { it.confirmed }
        val score = findings.maxOfOrNull { it.weight } ?: 0
        val verdict = when { confirmed -> Verdict.DANGEROUS; score >= 50 -> Verdict.SUSPICIOUS; else -> Verdict.NO_KNOWN_THREAT }
        val conf = when { confirmed -> Confidence.HIGH; score >= 80 -> Confidence.MEDIUM; else -> Confidence.LOW }
        return FileResult(cleanName, size, sha, type, verdict, conf, findings)
    }

    fun detectType(h: ByteArray, n: Int, open: (() -> InputStream)? = null): String {
        fun starts(vararg b: Int) = n >= b.size && b.indices.all { (h[it].toInt() and 0xff) == b[it] }
        val ascii = String(h, 0, minOf(n, 512), Charsets.ISO_8859_1)
        return when {
            starts(0x89, 0x50, 0x4E, 0x47) -> "png"
            starts(0xFF, 0xD8, 0xFF) -> "jpeg"
            ascii.startsWith("GIF8") -> "gif"
            ascii.startsWith("RIFF") && ascii.substring(8, minOf(12, ascii.length)) == "WEBP" -> "webp"
            n >= 12 && ascii.substring(4, 8) == "ftyp" && ascii.substring(8, 12).lowercase() in setOf("heic", "heix", "mif1", "msf1") -> "heic"
            n >= 12 && ascii.substring(4, 8) == "ftyp" -> "mp4"
            ascii.startsWith("%PDF") -> "pdf"
            starts(0x50, 0x4B, 0x03, 0x04) || starts(0x50, 0x4B, 0x05, 0x06) -> zipKind(open)
            ascii.startsWith("dex\n") -> "dex"
            starts(0x7F, 0x45, 0x4C, 0x46) -> "elf"
            ascii.startsWith("MZ") -> "pe"
            starts(0x1F, 0x8B) -> "gzip"
            ascii.startsWith("7z") && starts(0x37, 0x7A, 0xBC, 0xAF) -> "7z"
            ascii.startsWith("Rar!") -> "rar"
            starts(0xD0, 0xCF, 0x11, 0xE0) -> "ole"
            ascii.startsWith("#!") -> "script"
            Regex("(?is)^\\s*(<!doctype html|<html|<script)").containsMatchIn(ascii) -> "html"
            n > 0 && h.take(n).all { (it.toInt() and 0xff).let { b -> b == 9 || b == 10 || b == 13 || b in 32..126 || b >= 128 } } -> "text"
            else -> "unknown"
        }
    }

    private fun zipKind(open: (() -> InputStream)?): String {
        if (open == null) return "zip"
        var manifest = false; var dex = false; var office = false; var count = 0
        try {
            ZipInputStream(BufferedInputStream(open())).use { z ->
                while (count < 200) {
                    val e = z.nextEntry ?: break; count++
                    when {
                        e.name == "AndroidManifest.xml" -> manifest = true
                        e.name.matches(Regex("classes\\d*\\.dex")) -> dex = true
                        e.name == "[Content_Types].xml" -> office = true
                    }
                }
            }
        } catch (e: Exception) { return "zip" }
        return when { manifest && dex -> "apk"; office -> "office"; else -> "zip" }
    }

    private fun scanZip(input: InputStream, outerSize: Long, depth: Int, f: MutableList<Finding>, kind: String) {
        var entries = 0; var total = 0L
        val buf = ByteArray(64 * 1024)
        try {
            ZipInputStream(BufferedInputStream(input)).use { z ->
                while (true) {
                    val e: ZipEntry = z.nextEntry ?: break
                    entries++
                    if (entries > limits.maxZipEntries) {
                        f += Finding("zip-entries", "Υπερβολικά πολλά αρχεία μέσα στο συμπιεσμένο (>${limits.maxZipEntries}). Ο έλεγχος σταμάτησε με ασφάλεια.", weight = 60); return
                    }
                    val n = e.name
                    if (n.contains("../") || n.startsWith("/") || n.contains("..\\"))
                        f += Finding("zip-slip", "Περιέχει διαδρομή που βγαίνει έξω από τον φάκελο («$n»).", weight = 80)
                    val lower = n.lowercase()
                    val innerExt = lower.substringAfterLast('.', "")
                    if (kind == "zip" && innerExt in executableExt)
                        f += Finding("zip-exec", "Περιέχει εκτελέσιμο αρχείο: «$n».", weight = if (innerExt == "apk") 45 else 55)
                    val isNested = kind == "zip" && innerExt in setOf("zip", "apk", "jar")
                    // Μετράμε ΠΡΑΓΜΑΤΙΚΑ bytes — δεν εμπιστευόμαστε τις δηλωμένες τιμές της κεφαλίδας.
                    var entryBytes = 0L
                    var head: ByteArray? = if (lower.endsWith(".txt") || lower.endsWith(".com") || isNested || entries <= 50) ByteArray(256) else null
                    var headN = 0
                    while (true) {
                        val r = z.read(buf); if (r < 0) break
                        if (head != null && headN < head.size) { val c = minOf(r, head.size - headN); System.arraycopy(buf, 0, head, headN, c); headN += c }
                        entryBytes += r; total += r
                        if (total > limits.maxZipTotalUncompressed) {
                            f += Finding("zip-bomb", "Το συμπιεσμένο αποσυμπιέζεται σε πάνω από ${limits.maxZipTotalUncompressed / 1024 / 1024} MB. Πιθανή «βόμβα συμπίεσης» — ο έλεγχος σταμάτησε με ασφάλεια.", weight = 80); return
                        }
                    }
                    if (head != null && String(head, 0, headN, Charsets.ISO_8859_1).contains(EICAR_MARK))
                        f += Finding("zip-eicar", "Περιέχει το αρχείο δοκιμής EICAR («$n»).", confirmed = true, weight = 100)
                    if (e.compressedSize in 1..Long.MAX_VALUE && entryBytes / e.compressedSize.toDouble() > limits.maxZipRatio && entryBytes > 10 * 1024 * 1024)
                        f += Finding("zip-ratio", "Ασυνήθιστα μεγάλη αναλογία συμπίεσης στο «$n».", weight = 60)
                }
            }
        } catch (e: Exception) {
            val msg = e.message.orEmpty()
            if (msg.contains("encrypted", true)) f += Finding("zip-encrypted", "Κρυπτογραφημένο συμπιεσμένο — δεν μπορεί να ελεγχθεί το περιεχόμενο. Συχνό σε απάτες.", weight = 50)
            else f += Finding("zip-corrupt", "Το συμπιεσμένο είναι κατεστραμμένο ή ασυνήθιστο και δεν ελέγχθηκε πλήρως.", weight = 30)
        }
        if (outerSize > 0 && total / outerSize.toDouble() > limits.maxZipRatio && total > 50L * 1024 * 1024)
            f += Finding("zip-ratio-total", "Συνολική αναλογία συμπίεσης ${"%.0f".format(total / outerSize.toDouble())}:1 — πιθανή βόμβα συμπίεσης.", weight = 70)
    }

    private fun scanPdf(open: () -> InputStream, f: MutableList<Finding>) {
        val buf = ByteArray(limits.pdfScanBytes)
        val n = open().use { readFully(it, buf) }
        val s = String(buf, 0, n, Charsets.ISO_8859_1)
        val js = Regex("/(JavaScript|JS)\\b").containsMatchIn(s)
        val launch = s.contains("/Launch")
        val embedded = s.contains("/EmbeddedFile")
        val auto = Regex("/(OpenAction|AA)\\b").containsMatchIn(s)
        if (launch) f += Finding("pdf-launch", "Το PDF προσπαθεί να εκτελέσει εξωτερικό πρόγραμμα (/Launch).", weight = 80)
        if (js && auto) f += Finding("pdf-autojs", "Το PDF εκτελεί JavaScript αυτόματα με το άνοιγμα.", weight = 65)
        else if (js) f += Finding("pdf-js", "Το PDF περιέχει JavaScript.", weight = 35)
        if (embedded) f += Finding("pdf-embed", "Το PDF περιέχει ενσωματωμένα αρχεία.", weight = 35)
    }

    private fun expectedTypeForExt(ext: String) = when (ext) {
        "png" -> "png"; "jpg", "jpeg" -> "jpeg"; "gif" -> "gif"; "webp" -> "webp"; "pdf" -> "pdf"
        "zip" -> "zip"; "apk" -> "apk"; "docx", "xlsx", "pptx" -> "office"; else -> null
    }

    fun typeTitle(t: String) = when (t) {
        "apk" -> "εφαρμογή Android (APK)"; "pe" -> "πρόγραμμα Windows (.exe)"; "elf" -> "πρόγραμμα Linux"
        "dex" -> "κώδικας Android (DEX)"; "script" -> "αρχείο εντολών"; "zip" -> "συμπιεσμένο ZIP"
        "office" -> "έγγραφο Office"; "jpeg" -> "φωτογραφία JPEG"; "png" -> "εικόνα PNG"; "pdf" -> "PDF"
        "html" -> "ιστοσελίδα HTML"; "text" -> "κείμενο"; else -> t.uppercase()
    }

    private fun readFully(i: InputStream, b: ByteArray): Int {
        var n = 0
        while (n < b.size) { val r = i.read(b, n, b.size - n); if (r < 0) break; n += r }
        return n
    }

    private fun sha256(i: InputStream, max: Long): String {
        val md = MessageDigest.getInstance("SHA-256"); val b = ByteArray(64 * 1024); var tot = 0L
        while (true) { val r = i.read(b); if (r < 0) break; md.update(b, 0, r); tot += r; if (tot > max) break }
        return md.digest().joinToString("") { "%02x".format(it) }
    }
}
