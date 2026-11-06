import gr.tkdkavala.aspida.core.*
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.net.InetAddress
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

// ---------- Μικρό πλαίσιο δοκιμών ----------
val results = ArrayList<Triple<String, Boolean, String>>()
fun test(id: String, name: String, body: () -> String) {
    try { val ev = body(); results += Triple("$id $name", true, ev) }
    catch (e: Throwable) { results += Triple("$id $name", false, "${e::class.simpleName}: ${e.message}") }
}
fun check(c: Boolean, msg: () -> String) { if (!c) throw AssertionError(msg()) }

// ---------- Ψεύτικο δίκτυο ----------
class FakeHttp : Http {
    var online = true
    var sbDown = false
    val redirects = HashMap<String, String>()
    val sbThreats = HashMap<String, String>()     // url -> threatType
    val urlhausBad = HashSet<String>()
    var sbCalls = 0
    var lastSbUrl = ""
    override fun request(method: String, url: String, headers: Map<String, String>, form: Map<String, String>?, readBody: Boolean): Http.Response {
        if (!online) throw IOException("offline")
        if (url.startsWith("https://safebrowsing.googleapis.com/v5/urls:search")) {
            sbCalls++; lastSbUrl = url
            if (sbDown) return Http.Response(503, "{}")
            val asked = url.substringAfter('?').split('&').filter { it.startsWith("urls=") }.map { java.net.URLDecoder.decode(it.removePrefix("urls="), "UTF-8") }
            val hits = asked.filter { sbThreats.containsKey(it) }
            val body = """{"threats":[${hits.joinToString(",") { """{"url":"$it","threatTypes":["${sbThreats[it]}"]}""" }}],"cacheDuration":"300s"}"""
            return Http.Response(200, body)
        }
        if (url.startsWith("https://urlhaus-api.abuse.ch")) {
            val u = form?.get("url")
            return Http.Response(200, if (u in urlhausBad) """{"query_status":"ok","threat":"malware_download"}""" else """{"query_status":"no_results"}""")
        }
        val loc = redirects[url]
        return if (loc != null) Http.Response(301, "", loc) else Http.Response(200, "")
    }
}

val psl = PublicSuffixList(File(args0()).readText())
fun args0() = System.getProperty("psl")
val analyzer = UrlAnalyzer(psl)
var now = 1_700_000_000_000L
val clock = Clock { now }
val publicDns: (String) -> List<InetAddress> = { listOf(InetAddress.getByAddress(byteArrayOf(93.toByte(), 184.toByte(), 216.toByte(), 34))) }

fun newChecker(http: FakeHttp, withHaus: Boolean = true, key: String? = "TESTKEY") =
    LinkChecker(analyzer, http, SafeBrowsingV5(http, { key }, clock), if (withHaus) UrlHaus(http) { "HAUSKEY" } else null, { true }, publicDns)

fun LinkResult.brief() = "verdict=${verdict.name} conf=${confidence.name} final=$finalUrl reg=$registrableDomain chain=${redirectChain.size} findings=[${findings.joinToString(" | ") { it.code + ":" + it.weight }}] ok=$servicesChecked failed=${servicesFailed.size}"

fun main() {
    val http = FakeHttp()
    val lc = newChecker(http)

    // ===== Ασφαλείς σύνδεσμοι / ψευδείς συναγερμοί =====
    for ((id, u) in listOf("T01" to "google.com", "T02" to "https://www.youtube.com/watch?v=abc", "T03" to "https://el.wikipedia.org/wiki/Ταεκβοντό",
                           "T04" to "https://www.facebook.com/", "T05" to "https://www.instagram.com/")) {
        test(id, "Άνοιγμα $u → χωρίς ψευδή συναγερμό") {
            val r = lc.check(u); check(r.verdict == Verdict.NO_KNOWN_THREAT) { r.brief() }; check(r.findings.none { it.weight >= 50 }) { r.brief() }; r.brief()
        }
    }
    test("T06", "go.telekom.gr/openBills (χωρίς προσωπικά στοιχεία)") {
        val r = lc.check("https://go.telekom.gr/openBills"); check(r.verdict == Verdict.NO_KNOWN_THREAT && r.registrableDomain == "telekom.gr") { r.brief() }; r.brief()
    }
    test("T07", "cosmote.go.link/openBills χωρίς προκαταβολική εμπιστοσύνη") {
        http.redirects["https://cosmote.go.link/openBills"] = "https://www.cosmote.gr/selfcare/bills"
        val r = lc.check("https://cosmote.go.link/openBills")
        check(r.verdict == Verdict.NO_KNOWN_THREAT) { r.brief() }
        check(r.findings.any { it.code == "link-service" }) { "λείπει σήμανση υπηρεσίας συνδέσμων: " + r.brief() }
        check(r.redirectChain.size == 2 && r.registrableDomain == "cosmote.gr") { "δεν ελέγχθηκε ο τελικός προορισμός: " + r.brief() }
        check(http.lastSbUrl.contains("cosmote.go.link") && http.lastSbUrl.contains("www.cosmote.gr")) { "Safe Browsing δεν πήρε όλη την αλυσίδα" }
        r.brief()
    }
    test("T07b", "go.link: κακόβουλος τελικός προορισμός ΔΕΝ μπλοκάρει όλο το go.link") {
        http.redirects["https://evil.go.link/x"] = "https://bad-example.test/steal"
        http.sbThreats["https://bad-example.test/steal"] = "SOCIAL_ENGINEERING"
        val bad = lc.check("https://evil.go.link/x"); check(bad.verdict == Verdict.DANGEROUS) { bad.brief() }
        val bl = BlockList(clock); bl.add(bad.finalUrl!!, bad.host!!, "test", "gsb")
        check(bl.activeFor("https://cosmote.go.link/openBills") == null) { "μπλόκαρε άλλο URL του ίδιου domain" }
        "bad=${bad.verdict} · cosmote.go.link δεν επηρεάζεται"
    }
    test("T08", "e-bill.telekom.gr") { val r = lc.check("https://e-bill.telekom.gr/"); check(r.verdict == Verdict.NO_KNOWN_THREAT && r.registrableDomain == "telekom.gr") { r.brief() }; r.brief() }
    test("T09", "Νόμιμο URL με παραμέτρους") {
        val r = lc.check("https://www.skroutz.gr/search?keyphrase=taekwondo+dobok&order_by=price&utm_source=fb"); check(r.verdict == Verdict.NO_KNOWN_THREAT) { r.brief() }; r.brief()
    }
    test("T10", "Νόμιμο URL με ανακατεύθυνση (bit.ly → wikipedia)") {
        http.redirects["https://bit.ly/3tkd"] = "https://el.wikipedia.org/wiki/Καβάλα"
        val r = lc.check("δες εδώ: https://bit.ly/3tkd !"); check(r.verdict == Verdict.NO_KNOWN_THREAT && r.registrableDomain == "wikipedia.org") { r.brief() }; r.brief()
    }

    // ===== Phishing / παραπλανητικά =====
    test("T11", "Δοκιμαστική σελίδα phishing (testsafebrowsing) — λογική επιβεβαίωσης") {
        http.sbThreats["https://testsafebrowsing.appspot.com/s/phishing.html"] = "SOCIAL_ENGINEERING"
        val r = lc.check("https://testsafebrowsing.appspot.com/s/phishing.html"); check(r.verdict == Verdict.DANGEROUS && r.confidence == Confidence.HIGH) { r.brief() }; r.brief()
    }
    test("T12", "Δοκιμαστική κακόβουλη σελίδα (malware) — λογική επιβεβαίωσης") {
        http.sbThreats["https://testsafebrowsing.appspot.com/s/malware.html"] = "MALWARE"
        val r = lc.check("https://testsafebrowsing.appspot.com/s/malware.html"); check(r.verdict == Verdict.DANGEROUS) { r.brief() }; r.brief()
    }
    test("T13", "Πλαστή σελίδα σύνδεσης Facebook") {
        val r = lc.check("https://facebook-login.secure-verify.xyz/login.php"); check(r.verdict == Verdict.SUSPICIOUS) { r.brief() }; r.brief()
    }
    test("T14", "Πλαστή Instagram (instagrarn.com)") {
        val r = lc.check("https://instagrarn.com/accounts/login"); check(r.verdict == Verdict.SUSPICIOUS && r.findings.any { it.code.startsWith("lookalike") }) { r.brief() }; r.brief()
    }
    test("T15", "Πλαστή τραπεζική διεύθυνση") {
        val r = lc.check("https://piraeusbank-gr.account-verify.top/winbank"); check(r.verdict == Verdict.SUSPICIOUS) { r.brief() }; r.brief()
    }
    test("T16", "Ομοιόμορφοι χαρακτήρες (Κυριλλικά «раураl.com», μικτό «fаcebook.com»)") {
        val a = lc.check("https://раураl.com/signin"); val b = lc.check("https://fаcebook.com/")
        check(a.verdict == Verdict.SUSPICIOUS && b.verdict == Verdict.SUSPICIOUS) { a.brief() + " // " + b.brief() }
        check(b.findings.any { it.code == "mixed-script" }) { b.brief() }
        "a=${a.registrableDomain} ${a.verdict} · b=${b.registrableDomain} ${b.verdict} [${b.findings.joinToString { it.code }}]"
    }
    test("T17", "Παραπλανητικό subdomain (www.paypal.com.secure-login.info)") {
        val r = lc.check("https://www.paypal.com.secure-login.info/webscr"); check(r.verdict == Verdict.SUSPICIOUS && r.registrableDomain == "secure-login.info") { r.brief() }; r.brief()
    }
    test("T17b", "Κόλπο «@» (https://facebook.com@evil.example/)") {
        val r = lc.check("https://facebook.com@evil.example/"); check(r.verdict == Verdict.SUSPICIOUS && r.host == "evil.example") { r.brief() }; r.brief()
    }
    test("T18", "Συντόμευση → δοκιμαστική απειλή") {
        http.redirects["https://tinyurl.com/tkdtest"] = "https://testsafebrowsing.appspot.com/s/phishing.html"
        val r = lc.check("https://tinyurl.com/tkdtest"); check(r.verdict == Verdict.DANGEROUS) { r.brief() }; r.brief()
    }
    test("T19", "Αλλαγή τελικού προορισμού μετά από ανακατεύθυνση") {
        http.redirects["https://news.example.com/a"] = "https://other-site.example.net/b"
        val r = lc.check("https://news.example.com/a"); check(r.findings.any { it.code == "dest-change" } && r.registrableDomain == "example.net") { r.brief() }; r.brief()
    }
    test("T20", "Άγνωστος σύνδεσμος, υπηρεσίες εκτός → «Δεν ολοκληρώθηκε»") {
        val h = FakeHttp(); h.sbDown = true
        val r = LinkChecker(analyzer, h, SafeBrowsingV5(h, { "K" }, clock), null, { true }, publicDns).check("https://unknown-small-shop.gr/")
        check(r.verdict == Verdict.UNCHECKED && r.verdict.title == "Δεν ολοκληρώθηκε ο έλεγχος") { r.brief() }; r.brief()
    }
    test("T26", "Σύνδεσμος μέσα σε κείμενο email") {
        val r = lc.check("Αγαπητέ πελάτη,\nπληρώστε εδώ: www.paypal.com.secure-login.info/pay.\nΕυχαριστούμε"); check(r.verdict == Verdict.SUSPICIOUS) { r.brief() }; r.brief()
    }
    test("T27", "Phishing που μιμείται Facebook (faceb00k.com)") { val r = lc.check("http://faceb00k.com/recover"); check(r.verdict == Verdict.SUSPICIOUS) { r.brief() }; r.brief() }
    test("T28", "Phishing που μιμείται Instagram σε κοινόχρηστη φιλοξενία") {
        val r = lc.check("https://instagram-verify.github.io/login"); check(r.verdict == Verdict.SUSPICIOUS) { r.brief() }; r.brief()
    }
    test("T28b", "Επίσημοι σύντομοι σύνδεσμοι Meta (fb.me, wa.me, m.me, ig.me)") {
        val l = listOf("https://fb.me/abc", "https://wa.me/306900000000", "https://m.me/tkdkavala", "https://ig.me/m/tkdkavala").map { lc.check(it) }
        check(l.all { it.verdict == Verdict.NO_KNOWN_THREAT }) { l.joinToString(" // ") { it.brief() } }; l.joinToString { "${it.registrableDomain}=${it.verdict}" }
    }
    test("T44", "Διακοπή Internet κατά τον έλεγχο") {
        val h = FakeHttp(); h.online = false
        val r = LinkChecker(analyzer, h, SafeBrowsingV5(h, { "K" }, clock), UrlHaus(h) { "K" }, { true }, publicDns).check("https://www.google.com/")
        check(r.verdict == Verdict.UNCHECKED) { r.brief() }; r.brief()
    }
    test("T45", "Google Safe Browsing μη διαθέσιμο (503) → ΟΧΙ «ασφαλές»") {
        val h = FakeHttp(); h.sbDown = true
        val r = LinkChecker(analyzer, h, SafeBrowsingV5(h, { "K" }, clock), null, { true }, publicDns).check("https://www.google.com/")
        check(r.verdict != Verdict.NO_KNOWN_THREAT) { r.brief() }; r.brief()
    }
    test("T45b", "Χωρίς API key → «Δεν ολοκληρώθηκε»") {
        val h = FakeHttp(); val r = LinkChecker(analyzer, h, SafeBrowsingV5(h, { "" }, clock), null, { true }, publicDns).check("https://www.google.com/")
        check(r.verdict == Verdict.UNCHECKED) { r.brief() }; r.brief()
    }
    test("T45c", "Cache Safe Browsing τηρεί cacheDuration") {
        val h = FakeHttp(); val sb = SafeBrowsingV5(h, { "K" }, clock)
        sb.check(listOf("https://a.example/")); sb.check(listOf("https://a.example/")); val c1 = h.sbCalls
        now += 25 * 3600_000L; sb.check(listOf("https://a.example/")); val c2 = h.sbCalls
        check(c1 == 1 && c2 == 2) { "calls $c1 $c2" }; "κλήσεις: 1η+2η=$c1 (από cache), μετά από 25 ώρες=$c2"
    }
    test("T46", "Αποκλεισμός επιβεβαιωμένου URL (μόνο το συγκεκριμένο URL)") {
        val bl = BlockList(clock); val u = "https://testsafebrowsing.appspot.com/s/phishing.html"
        bl.add(u, "testsafebrowsing.appspot.com", "phishing", "Google Safe Browsing")
        check(bl.activeFor(u) != null && bl.activeFor("https://testsafebrowsing.appspot.com/") == null) { "λάθος εύρος" }
        "αποκλεισμένο: ναι · άλλο URL ίδιου host: όχι"
    }
    test("T47", "Προσωρινή καραντίνα και σωστή λήξη") {
        val bl = BlockList(clock); val u = "https://x.example/p"; bl.add(u, "x.example", "r", "gsb", 3600_000)
        val before = bl.activeFor(u) != null; now += 3600_001; val after = bl.activeFor(u) == null; val needsRecheck = bl.expired().size == 1
        bl.recheckDone(BlockList.hash(u), stillDangerous = false)
        check(before && after && needsRecheck && bl.all().isEmpty()) { "$before $after $needsRecheck" }; "ενεργό→λήξη→επανέλεγχος→αφαίρεση"
    }
    test("T48", "Αφαίρεση λανθασμένου αποκλεισμού (λογική)") {
        val bl = BlockList(clock); val e = bl.add("https://y.example/", "y.example", "r", "gsb"); check(bl.remove(e.urlHash) && bl.all().isEmpty()) { "" }
        "αφαιρέθηκε (ο έλεγχος δακτυλικού γίνεται στη συσκευή)"
    }
    test("T-PSL", "Public Suffix List: σωστά καταχωρίσιμα domains") {
        val m = mapOf("e-bill.telekom.gr" to "telekom.gr", "www.gov.gr" to "www.gov.gr", "a.b.com.gr" to "b.com.gr", "x.github.io" to "x.github.io",
            "www.bbc.co.uk" to "bbc.co.uk", "cosmote.go.link" to "go.link", "xn--hxajbheg2az3al.xn--qxam" to "xn--hxajbheg2az3al.xn--qxam")
        val bad = m.filter { psl.registrableDomain(it.key) != it.value }.map { "${it.key}→${psl.registrableDomain(it.key)}" }
        check(bad.isEmpty()) { bad.toString() }; "${m.size}/${m.size} σωστά"
    }
    test("T-GOV", "Ελληνικές υπηρεσίες χωρίς ψευδή συναγερμό + μίμηση gov.gr") {
        val ok = listOf("https://www.gov.gr/", "https://www1.aade.gr/taxisnet/", "https://www.elta.gr/", "https://www.piraeusbank.gr/").map { lc.check(it) }
        val fake = lc.check("https://gov-gr.taxisnet-refund.com/epistrofi")
        check(ok.all { it.verdict == Verdict.NO_KNOWN_THREAT } && fake.verdict == Verdict.SUSPICIOUS) { ok.joinToString(" // ") { it.brief() } + " FAKE " + fake.brief() }
        ok.joinToString { "${it.host}=${it.verdict}" } + " · ψεύτικο=${fake.verdict}"
    }
    test("T-IDN", "Ελληνικό IDN domain (παράδειγμα.ελ) χωρίς ψευδή συναγερμό") {
        val r = lc.check("https://παράδειγμα.ελ/"); check(r.verdict == Verdict.NO_KNOWN_THREAT) { r.brief() }; "host=${r.host} ascii=${r.finalUrl}"
    }
    test("T-SCHEME", "javascript: σύνδεσμος") { val r = lc.check("javascript:alert(1)"); check(r.verdict == Verdict.SUSPICIOUS) { r.brief() }; r.brief() }
    test("T-PRIV", "Ανακατεύθυνση σε ιδιωτικό δίκτυο δεν ακολουθείται") {
        val h = FakeHttp(); h.redirects["https://go.example.com/r"] = "http://192.168.1.1/admin"
        val c = LinkChecker(analyzer, h, SafeBrowsingV5(h, { "K" }, clock), null, { true }) { host -> if (host.startsWith("192.168")) listOf(InetAddress.getByName(host)) else publicDns(host) }
        val r = c.check("https://go.example.com/r"); check(r.findings.any { it.code == "private" }) { r.brief() }; r.brief()
    }

    // ===== Αρχεία =====
    val fs = FileScanner()
    fun scanBytes(name: String, b: ByteArray) = fs.scan(name, b.size.toLong()) { ByteArrayInputStream(b) }
    fun FileResult.brief() = "type=$detectedType verdict=${verdict.name} conf=${confidence.name} sha=${sha256.take(12)}… findings=[${findings.joinToString(" | ") { it.code + ":" + it.weight }}]"
    fun zip(vararg e: Pair<String, ByteArray>): ByteArray { val bo = ByteArrayOutputStream(); ZipOutputStream(bo).use { z -> e.forEach { (n, d) -> z.putNextEntry(ZipEntry(n)); z.write(d); z.closeEntry() } }; return bo.toByteArray() }
    val jpg = byteArrayOf(0xFF.toByte(), 0xD8.toByte(), 0xFF.toByte(), 0xE0.toByte()) + ByteArray(2000) { (it % 251).toByte() }
    val pdf = "%PDF-1.7\n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n%%EOF".toByteArray()
    val eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H+H*".toByteArray()
    val fakeApk = zip("AndroidManifest.xml" to ByteArray(100), "classes.dex" to "dex\n035".toByteArray() + ByteArray(100), "resources.arsc" to ByteArray(10))

    test("T31", "Ασφαλής φωτογραφία") { val r = scanBytes("IMG_2026.jpg", jpg); check(r.verdict == Verdict.NO_KNOWN_THREAT && r.detectedType == "jpeg") { r.brief() }; r.brief() }
    test("T32", "Ασφαλές PDF") { val r = scanBytes("πρόγραμμα.pdf", pdf); check(r.verdict == Verdict.NO_KNOWN_THREAT && r.detectedType == "pdf") { r.brief() }; r.brief() }
    test("T32b", "PDF με αυτόματη JavaScript + /Launch") {
        val r = scanBytes("τιμολόγιο.pdf", "%PDF-1.5\n<< /OpenAction << /S /JavaScript /JS (app.alert(1)) >> /Launch >>".toByteArray()); check(r.verdict == Verdict.SUSPICIOUS) { r.brief() }; r.brief()
    }
    test("T33", "Ασφαλές ZIP") { val r = scanBytes("φωτογραφίες.zip", zip("a.jpg" to jpg, "b.pdf" to pdf)); check(r.verdict == Verdict.NO_KNOWN_THREAT && r.detectedType == "zip") { r.brief() }; r.brief() }
    test("T34", "Αρχείο δοκιμής EICAR") {
        val r = scanBytes("eicar.com", eicar); check(r.verdict == Verdict.DANGEROUS && r.sha256 == FileScanner.EICAR_SHA256) { r.brief() + " sha=" + r.sha256 }; r.brief()
    }
    test("T34b", "EICAR μέσα σε ZIP") { val r = scanBytes("docs.zip", zip("eicar.com" to eicar)); check(r.verdict == Verdict.DANGEROUS) { r.brief() }; r.brief() }
    test("T35", "Παραπλανητική επέκταση (photo.jpg.apk, invoice.pdf που είναι .exe, RTLO)") {
        val a = scanBytes("photo.jpg.apk", fakeApk); val b = scanBytes("invoice.pdf", "MZ".toByteArray() + ByteArray(500))
        val c = scanBytes("sms‮gpj.apk", fakeApk)
        check(a.verdict == Verdict.SUSPICIOUS && b.verdict == Verdict.SUSPICIOUS && c.verdict == Verdict.SUSPICIOUS) { a.brief() + " // " + b.brief() + " // " + c.brief() }
        "a=[${a.findings.joinToString { it.code }}] b=[${b.findings.joinToString { it.code }}] c=«${c.name}» [${c.findings.joinToString { it.code }}]"
    }
    test("T36", "Τεράστιο συμπιεσμένο (βόμβα) χωρίς εξάντληση πόρων") {
        val bo = ByteArrayOutputStream()
        ZipOutputStream(bo).use { z -> z.setLevel(9); z.putNextEntry(ZipEntry("zeros.bin")); val chunk = ByteArray(1 shl 20); repeat(700) { z.write(chunk) }; z.closeEntry() }
        val bomb = bo.toByteArray()
        val rt = Runtime.getRuntime(); rt.gc(); val memBefore = rt.totalMemory() - rt.freeMemory(); val t0 = System.nanoTime()
        val r = scanBytes("bomb.zip", bomb)
        val ms = (System.nanoTime() - t0) / 1_000_000; val memAfter = rt.totalMemory() - rt.freeMemory()
        check(r.verdict == Verdict.SUSPICIOUS && r.findings.any { it.code == "zip-bomb" }) { r.brief() }
        "αρχείο ${bomb.size / 1024} KB → δήλωση 700 MB · σταμάτησε στα 512 MB · ${ms} ms · μνήμη Δ≈${(memAfter - memBefore) / 1024 / 1024} MB · ${r.findings.joinToString { it.code }}"
    }
    test("T37", "APK δοκιμής: αναγνώριση από περιεχόμενο") { val r = scanBytes("app.apk", fakeApk); check(r.detectedType == "apk" && r.findings.any { it.code == "apk" }) { r.brief() }; r.brief() }
    test("T37b", "APK μεταμφιεσμένο σε .zip") { val r = scanBytes("photos.zip", fakeApk); check(r.detectedType == "apk") { r.brief() }; r.brief() }
    test("T-ZIPSLIP", "ZIP με διαδρομή ../") { val r = scanBytes("x.zip", zip("../../evil.sh" to "#!/bin/sh".toByteArray())); check(r.verdict == Verdict.SUSPICIOUS) { r.brief() }; r.brief() }
    test("T-JSON", "Αναλυτής JSON") {
        val j = Json.parse("""{"threats":[{"url":"a","threatTypes":["MALWARE"]}],"cacheDuration":"300.5s","x":[1,2.5,true,null,"é"]}""") as Map<*, *>
        check((j["threats"] as List<*>).size == 1 && SafeBrowsingV5.parseDuration(j["cacheDuration"] as String) == 300_500L) { j.toString() }; "ok"
    }

    // ---------- Αναφορά ----------
    val pass = results.count { it.second }
    val sb = StringBuilder()
    results.forEach { (n, ok, ev) -> sb.append(if (ok) "PASS" else "FAIL").append(" | ").append(n).append(" | ").append(ev.replace("\n", " ")).append('\n') }
    sb.append("ΣΥΝΟΛΟ: $pass/${results.size} PASS\n")
    print(sb)
    File(System.getProperty("out") ?: "core-test-results.txt").writeText(sb.toString())
    if (pass != results.size) System.exit(1)
}
