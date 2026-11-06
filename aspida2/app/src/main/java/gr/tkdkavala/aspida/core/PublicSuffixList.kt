package gr.tkdkavala.aspida.core

/**
 * Υλοποίηση του αλγορίθμου Public Suffix List (publicsuffix.org).
 * Βρίσκει το «καταχωρίσιμο domain» (π.χ. e-bill.telekom.gr → telekom.gr,
 * cosmote.go.link → go.link) ώστε να μη μπερδεύονται υποτομείς με ιδιοκτήτη.
 * Τα domains της ενότητας PRIVATE (π.χ. github.io) θεωρούνται κοινόχρηστα.
 */
class PublicSuffixList(text: String) {
    private val rules = HashSet<String>()
    private val wildcards = HashSet<String>()
    private val exceptions = HashSet<String>()
    private val privateRules = HashSet<String>()

    init {
        var inPrivate = false
        text.lineSequence().forEach { raw ->
            val line = raw.trim()
            if (line.contains("===BEGIN PRIVATE DOMAINS===")) inPrivate = true
            if (line.isEmpty() || line.startsWith("//")) return@forEach
            val rule = java.net.IDN.toASCII(line.split(' ', '\t')[0].lowercase(), java.net.IDN.ALLOW_UNASSIGNED)
            when {
                rule.startsWith("!") -> exceptions.add(rule.substring(1))
                rule.startsWith("*.") -> wildcards.add(rule.substring(2))
                else -> rules.add(rule)
            }
            if (inPrivate) privateRules.add(rule.removePrefix("*.").removePrefix("!"))
        }
    }

    /** Δημόσια κατάληξη (π.χ. "com.gr"). Ο host πρέπει να είναι ASCII (punycode), πεζά. */
    fun publicSuffix(host: String): String {
        val labels = host.trimEnd('.').split('.')
        for (i in labels.indices) {
            val cand = labels.subList(i, labels.size).joinToString(".")
            if (exceptions.contains(cand)) return labels.subList(i + 1, labels.size).joinToString(".")
            if (rules.contains(cand)) return cand
            val parent = labels.subList(i + 1, labels.size).joinToString(".")
            if (i + 1 < labels.size && wildcards.contains(parent)) return cand
        }
        return labels.last() // προεπιλεγμένος κανόνας "*"
    }

    /** Καταχωρίσιμο domain ή null αν ο host είναι ο ίδιος δημόσια κατάληξη. */
    fun registrableDomain(host: String): String? {
        val h = host.trimEnd('.')
        val suffix = publicSuffix(h)
        if (h == suffix) return null
        val rest = h.removeSuffix(".$suffix")
        return rest.substringAfterLast('.') + "." + suffix
    }

    /** true αν η κατάληξη είναι από την ενότητα PRIVATE (κοινόχρηστη υπηρεσία φιλοξενίας). */
    fun isSharedHosting(host: String): Boolean {
        val s = publicSuffix(host.trimEnd('.'))
        return privateRules.contains(s) || privateRules.contains(s.substringAfter('.', ""))
    }
}
