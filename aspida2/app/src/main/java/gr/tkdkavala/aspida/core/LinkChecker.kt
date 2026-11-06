package gr.tkdkavala.aspida.core

import java.net.InetAddress

/**
 * Ολοκληρωμένος έλεγχος συνδέσμου:
 * 1) ανάλυση URL (IDN, punycode, PSL), 2) ακολούθηση ανακατευθύνσεων με όρια,
 * 3) Safe Browsing για ΟΛΑ τα βήματα, 4) URLhaus, 5) τοπικοί κανόνες μόνο ως υποψία.
 */
class LinkChecker(
    private val analyzer: UrlAnalyzer,
    private val http: Http,
    private val safeBrowsing: SafeBrowsingV5,
    private val urlHaus: UrlHaus?,
    private val followRedirects: () -> Boolean = { true },
    private val resolveDns: (String) -> List<InetAddress> = { InetAddress.getAllByName(it).toList() },
) {
    companion object {
        const val MAX_REDIRECTS = 6
        const val SUSPICION_THRESHOLD = 50
    }

    fun check(input: String): LinkResult {
        val urlText = analyzer.extractUrl(input) ?: input.trim()
        val first = analyzer.parse(urlText)
            ?: return LinkResult(input, null, null, null, Verdict.UNCHECKED, Confidence.LOW,
                listOf(Finding("parse", "Δεν αναγνωρίστηκε έγκυρος σύνδεσμος.")), emptyList(), emptyList(), emptyList())

        val findings = ArrayList<Finding>()
        findings += analyzer.localFindings(first)
        if (first.scheme != "http" && first.scheme != "https") {
            return LinkResult(input, null, null, null, Verdict.SUSPICIOUS, Confidence.MEDIUM, findings, emptyList(), emptyList(), emptyList())
        }

        val chain = arrayListOf(first.normalized)
        var last = first
        if (followRedirects()) {
            val r = followChain(first, chain, findings)
            if (r != null) last = r
        }
        if (last !== first) {
            findings += analyzer.localFindings(last).map { it.copy(message = "Τελικός προορισμός: " + it.message) }
            if (first.registrableDomain != null && last.registrableDomain != first.registrableDomain) {
                findings += Finding("dest-change", "Ο σύνδεσμος καταλήγει σε άλλο domain: ${first.registrableDomain} → ${last.registrableDomain ?: last.asciiHost}.", weight = 0)
            }
        }

        val checked = ArrayList<String>(); val failed = ArrayList<String>()
        try {
            safeBrowsing.check(chain).forEach { h ->
                findings += Finding("gsb", "Google Safe Browsing: επιβεβαιωμένη απειλή (${h.types.joinToString { threatName(it) }}).", confirmed = true, weight = 100)
            }
            checked += safeBrowsing.name
        } catch (e: ServiceUnavailable) { failed += "${safeBrowsing.name}: ${e.message}" }

        if (urlHaus != null) {
            try {
                chain.forEach { u -> urlHaus.check(u)?.let { h -> findings += Finding("urlhaus", "URLhaus: ο σύνδεσμος διανέμει κακόβουλο λογισμικό (${h.types.joinToString()}).", confirmed = true, weight = 100) } }
                checked += urlHaus.name
            } catch (e: ServiceUnavailable) { failed += "${urlHaus.name}: ${e.message}" }
        }

        val confirmed = findings.any { it.confirmed }
        val score = findings.maxOfOrNull { it.weight } ?: 0
        val verdict = when {
            confirmed -> Verdict.DANGEROUS
            score >= SUSPICION_THRESHOLD -> Verdict.SUSPICIOUS
            checked.isEmpty() -> Verdict.UNCHECKED
            else -> Verdict.NO_KNOWN_THREAT
        }
        val confidence = when {
            confirmed -> Confidence.HIGH
            verdict == Verdict.SUSPICIOUS && score >= 80 -> Confidence.MEDIUM
            verdict == Verdict.SUSPICIOUS -> Confidence.LOW
            verdict == Verdict.NO_KNOWN_THREAT && failed.isEmpty() -> Confidence.MEDIUM
            else -> Confidence.LOW
        }
        return LinkResult(input, last.normalized, last.unicodeHost, last.registrableDomain, verdict, confidence,
            findings.distinctBy { it.code to it.message }, chain, checked, failed)
    }

    private fun followChain(start: ParsedUrl, chain: MutableList<String>, findings: MutableList<Finding>): ParsedUrl? {
        var cur = start
        repeat(MAX_REDIRECTS) {
            if (isPrivateHost(cur.asciiHost)) {
                findings += Finding("private", "Ο σύνδεσμος οδηγεί σε εσωτερική/ιδιωτική διεύθυνση δικτύου (${cur.asciiHost}). Δεν ακολουθήθηκε.", weight = 55)
                return cur
            }
            val resp = try {
                val h = http.request("HEAD", cur.normalized, readBody = false)
                if (h.code == 405 || h.code == 501) http.request("GET", cur.normalized, readBody = false) else h
            } catch (e: Exception) {
                findings += Finding("redirect-fail", "Δεν ήταν δυνατή η ανίχνευση ανακατεύθυνσης (χωρίς σύνδεση ή ο διακομιστής δεν απάντησε).", weight = 0)
                return cur
            }
            if (resp.code !in 300..399 || resp.location.isNullOrBlank()) return cur
            val nextRaw = resolve(cur.normalized, resp.location)
            val next = analyzer.parse(nextRaw) ?: return cur
            if (next.scheme != "http" && next.scheme != "https") {
                findings += Finding("redirect-scheme", "Ανακατεύθυνση σε μη-ιστοσελίδα «${next.scheme}:».", weight = 60)
                return cur
            }
            if (chain.contains(next.normalized)) return next
            chain += next.normalized
            cur = next
        }
        findings += Finding("redirect-loop", "Υπερβολικά πολλές ανακατευθύνσεις (>$MAX_REDIRECTS).", weight = 40)
        return cur
    }

    private fun resolve(base: String, loc: String): String = try {
        java.net.URI(base).resolve(loc.trim().replace(" ", "%20")).toString()
    } catch (e: Exception) { loc }

    private fun isPrivateHost(host: String): Boolean {
        if (host == "localhost" || host.endsWith(".local") || host.endsWith(".internal")) return true
        val addrs = try { resolveDns(host.trim('[', ']')) } catch (e: Exception) { return false }
        return addrs.any { it.isLoopbackAddress || it.isSiteLocalAddress || it.isLinkLocalAddress || it.isAnyLocalAddress }
    }

    private fun threatName(t: String) = when (t) {
        "SOCIAL_ENGINEERING" -> "phishing/εξαπάτηση"
        "MALWARE" -> "κακόβουλο λογισμικό"
        "UNWANTED_SOFTWARE" -> "ανεπιθύμητο λογισμικό"
        "POTENTIALLY_HARMFUL_APPLICATION" -> "επιβλαβής εφαρμογή"
        else -> t
    }
}
