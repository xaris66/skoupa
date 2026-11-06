package gr.tkdkavala.aspida.core

import java.net.IDN
import java.net.URI

/** Αποτέλεσμα ανάλυσης ενός URL (χωρίς δίκτυο). */
data class ParsedUrl(
    val original: String,
    val normalized: String,
    val scheme: String,
    val asciiHost: String,
    val unicodeHost: String,
    val registrableDomain: String?,
    val isIpLiteral: Boolean,
    val hasUserInfo: Boolean,
)

class UrlAnalyzer(private val psl: PublicSuffixList) {

    /** Βρίσκει το πρώτο URL μέσα σε κείμενο (π.χ. από κοινή χρήση μηνύματος). */
    fun extractUrl(text: String): String? {
        val m = Regex("""(?i)\b((?:https?://|www\.)[^\s<>"'«»]+)""").find(text) ?: return null
        var u = m.groupValues[1].trimEnd('.', ',', ')', ']', '!', '?', ';', ':')
        if (u.startsWith("www.", ignoreCase = true)) u = "https://$u"
        return u
    }

    fun parse(input: String): ParsedUrl? {
        val raw = input.trim().replace(Regex("[\\u200B-\\u200F\\u202A-\\u202E\\u2066-\\u2069]"), "")
        if (raw.isEmpty() || raw.length > 8192) return null
        val withScheme = if (Regex("^[a-zA-Z][a-zA-Z0-9+.-]*:").containsMatchIn(raw)) raw else "https://$raw"
        val scheme = withScheme.substringBefore(':').lowercase()
        if (scheme != "http" && scheme != "https") {
            return ParsedUrl(raw, raw, scheme, "", "", null, false, false)
        }
        // Χειροκίνητη εξαγωγή authority ώστε να δουλεύουν και Unicode hosts.
        val afterScheme = withScheme.substringAfter("://", "")
        val authority = afterScheme.takeWhile { it != '/' && it != '?' && it != '#' }
        val rest = afterScheme.substring(authority.length)
        val hasUserInfo = authority.contains('@')
        val hostPort = authority.substringAfterLast('@')
        val isV6 = hostPort.startsWith("[")
        val hostRaw = if (isV6) hostPort.substringBefore(']') + "]" else hostPort.substringBefore(':')
        val port = if (isV6) hostPort.substringAfter("]", "").removePrefix(":") else hostPort.substringAfter(':', "")
        if (hostRaw.isEmpty()) return null
        val lower = hostRaw.lowercase().trimEnd('.')
        val ascii = try {
            if (isV6) lower else IDN.toASCII(lower, IDN.ALLOW_UNASSIGNED)
        } catch (e: IllegalArgumentException) { return null }
        val unicode = try { if (isV6) lower else IDN.toUnicode(ascii, IDN.ALLOW_UNASSIGNED) } catch (e: Exception) { lower }
        val isIp = isV6 || Regex("^\\d{1,3}(\\.\\d{1,3}){3}$").matches(ascii) || Regex("^(0x[0-9a-f]+|\\d{8,10})$").matches(ascii)
        val reg = if (isIp) null else psl.registrableDomain(ascii)
        val portPart = if (port.isNotEmpty() && !((scheme == "https" && port == "443") || (scheme == "http" && port == "80"))) ":$port" else ""
        val path = rest.substringBefore('#').ifEmpty { "/" }
        val normalized = "$scheme://$ascii$portPart$path"
        try { URI(normalized) } catch (e: Exception) { /* ανεκτικοί στα περίεργα paths */ }
        return ParsedUrl(raw, normalized, scheme, ascii, unicode, reg, isIp, hasUserInfo)
    }

    /** Τοπικοί κανόνες: δίνουν ΜΟΝΟ υποψία, ποτέ επιβεβαιωμένη απειλή. */
    fun localFindings(p: ParsedUrl): List<Finding> {
        val f = ArrayList<Finding>()
        if (p.scheme != "http" && p.scheme != "https") {
            val w = if (p.scheme in setOf("javascript", "data", "vbscript", "file")) 90 else 40
            f += Finding("scheme", "Ασυνήθιστος τύπος συνδέσμου «${p.scheme}:» — δεν είναι κανονική ιστοσελίδα.", weight = w)
            return f
        }
        if (p.scheme == "http") f += Finding("http", "Χωρίς κρυπτογράφηση (http). Μην πληκτρολογήσεις κωδικούς εδώ.", weight = 15)
        if (p.hasUserInfo) f += Finding("userinfo", "Ο σύνδεσμος έχει «@» πριν από τη διεύθυνση — κλασικό κόλπο παραπλάνησης. Ο πραγματικός προορισμός είναι: ${p.unicodeHost}", weight = 70)
        if (p.isIpLiteral) f += Finding("ip", "Η διεύθυνση είναι σκέτη IP (${p.asciiHost}) αντί για όνομα ιστοσελίδας.", weight = 35)
        if (p.asciiHost.isEmpty() || p.isIpLiteral) return f

        val labels = p.unicodeHost.split('.')
        val regLabel = p.registrableDomain?.let { IDN.toUnicode(it, IDN.ALLOW_UNASSIGNED).substringBefore('.') } ?: ""

        // Μείξη αλφαβήτων μέσα στην ίδια λέξη (π.χ. Λατινικά + Κυριλλικά).
        labels.forEach { label ->
            val scripts = label.filter { it.isLetter() }.map { scriptOf(it) }.toSet()
            if (scripts.size > 1) f += Finding("mixed-script", "Το όνομα «$label» αναμειγνύει γράμματα από διαφορετικά αλφάβητα (${scripts.joinToString()}). Συχνό τέχνασμα μίμησης.", weight = 75)
        }

        val viaLinkService = Brands.linkServices.contains(p.asciiHost) || Brands.linkServices.contains(p.registrableDomain)
        val loginWords = Regex("(?i)(login|log-in|signin|sign-in|verify|verification|account|secure|update|confirm|password|wallet|unlock|support|recovery)")
        val loginBait = loginWords.containsMatchIn(p.normalized)

        for (brand in Brands.all) {
            if (Brands.isOfficial(brand, p.registrableDomain)) continue
            // 1) Μίμηση στο κύριο όνομα (faceb00k.com, іnstagram.com, instagrarn.com)
            val skel = skeleton(regLabel)
            val lookalike = brand.tokens.any { t ->
                val st = skeleton(t)
                skel == st || (st.length >= 6 && levenshtein(skel, st) == 1)
            }
            if (lookalike && regLabel.isNotEmpty()) {
                f += Finding("lookalike-${brand.name}", "Το «${p.registrableDomain?.let { IDN.toUnicode(it) }}» μοιάζει με ${brand.name} αλλά ΔΕΝ είναι επίσημη διεύθυνση της.", weight = 85)
                continue
            }
            // 2) Όνομα εταιρείας σε υποτομέα/λέξη ξένου domain (facebook.com.login-secure.xyz)
            val inLabels = labels.dropLast(1).any { l -> brand.tokens.any { t -> l == t || l.split('-').contains(t) || (t.length >= 6 && l.contains(t)) } }
            if (inLabels && !viaLinkService) {
                val shared = psl.isSharedHosting(p.asciiHost)
                val w = when { loginBait -> 70; shared -> 60; else -> 50 }
                f += Finding("brand-mismatch-${brand.name}", "Αναφέρει «${brand.name}» αλλά ο πραγματικός ιδιοκτήτης είναι το «${p.registrableDomain}», όχι επίσημη διεύθυνση της ${brand.name}.", weight = w)
            }
        }
        if (viaLinkService) f += Finding("link-service", "Περνάει από υπηρεσία συντόμευσης/έξυπνων συνδέσμων (${p.registrableDomain}). Ελέγχεται ο τελικός προορισμός.", weight = 0)
        if (labels.size > 5) f += Finding("deep-subdomains", "Πολλά επίπεδα υποτομέων (${labels.size}).", weight = 15)
        if (p.normalized.length > 2000) f += Finding("long", "Ασυνήθιστα μεγάλος σύνδεσμος.", weight = 10)
        return f
    }

    companion object {
        fun scriptOf(c: Char): String = when (Character.UnicodeScript.of(c.code)) {
            Character.UnicodeScript.LATIN -> "Λατινικά"
            Character.UnicodeScript.CYRILLIC -> "Κυριλλικά"
            Character.UnicodeScript.GREEK -> "Ελληνικά"
            Character.UnicodeScript.ARMENIAN -> "Αρμένικα"
            else -> Character.UnicodeScript.of(c.code).name
        }

        private val confusables = mapOf(
            'а' to 'a', 'е' to 'e', 'о' to 'o', 'р' to 'p', 'с' to 'c', 'у' to 'y', 'х' to 'x', 'і' to 'i', 'ј' to 'j', 'ѕ' to 's', 'ԁ' to 'd', 'һ' to 'h', 'ⅼ' to 'l', 'ɡ' to 'g',
            'α' to 'a', 'ο' to 'o', 'ε' to 'e', 'ι' to 'i', 'κ' to 'k', 'ν' to 'v', 'τ' to 't', 'υ' to 'u', 'ρ' to 'p', 'χ' to 'x', 'η' to 'n',
            '0' to 'o', '1' to 'l', '3' to 'e', '4' to 'a', '5' to 's', '7' to 't', '@' to 'a', '$' to 's',
        )

        /** «Σκελετός» για σύγκριση: αφαιρεί τόνους, ενώνει όμοια σύμβολα, rn→m, vv→w. */
        fun skeleton(s: String): String {
            val n = java.text.Normalizer.normalize(s.lowercase(), java.text.Normalizer.Form.NFKD).replace(Regex("\\p{M}"), "")
            val mapped = n.map { confusables[it] ?: it }.joinToString("")
            // rn→m, vv→w, l→i (μιμήσεις τύπου instagrarn, paypai)
            return mapped.replace("rn", "m").replace("vv", "w").replace("-", "").replace('l', 'i')
        }

        fun levenshtein(a: String, b: String): Int {
            if (kotlin.math.abs(a.length - b.length) > 2) return 99
            val d = IntArray(b.length + 1) { it }
            for (i in 1..a.length) {
                var prev = d[0]; d[0] = i
                for (j in 1..b.length) {
                    val tmp = d[j]
                    d[j] = minOf(d[j] + 1, d[j - 1] + 1, prev + if (a[i - 1] == b[j - 1]) 0 else 1)
                    prev = tmp
                }
            }
            return d[b.length]
        }
    }
}
