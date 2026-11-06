package gr.tkdkavala.aspida.core

/**
 * Επίπεδα αποτελέσματος. Η Ασπίδα ΠΟΤΕ δεν λέει «Ασφαλές»:
 * λέει «Δεν βρέθηκε γνωστή απειλή» μόνο όταν ο έλεγχος ολοκληρώθηκε.
 */
enum class Verdict(val title: String) {
    NO_KNOWN_THREAT("Δεν βρέθηκε γνωστή απειλή"),
    SUSPICIOUS("Ύποπτο — πρόσεξε"),
    DANGEROUS("Επικίνδυνο — επιβεβαιωμένη απειλή"),
    UNCHECKED("Δεν ολοκληρώθηκε ο έλεγχος"),
}

enum class Confidence(val title: String) { LOW("χαμηλή"), MEDIUM("μέτρια"), HIGH("υψηλή") }

data class Finding(
    val code: String,
    val message: String,
    /** true = επιβεβαιωμένη απειλή από βάση απειλών ή γνωστή υπογραφή */
    val confirmed: Boolean = false,
    /** βάρος υποψίας 0..100 για τοπικούς κανόνες */
    val weight: Int = 0,
)

data class LinkResult(
    val inputUrl: String,
    val finalUrl: String?,
    val host: String?,
    val registrableDomain: String?,
    val verdict: Verdict,
    val confidence: Confidence,
    val findings: List<Finding>,
    val redirectChain: List<String>,
    val servicesChecked: List<String>,
    val servicesFailed: List<String>,
)

data class FileResult(
    val name: String,
    val size: Long,
    val sha256: String,
    val detectedType: String,
    val verdict: Verdict,
    val confidence: Confidence,
    val findings: List<Finding>,
)

/** Ρολόι που μπορεί να αλλάξει στις δοκιμές. */
fun interface Clock { fun now(): Long }
val SystemClock = Clock { System.currentTimeMillis() }
