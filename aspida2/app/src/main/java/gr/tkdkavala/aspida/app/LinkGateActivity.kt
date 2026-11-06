package gr.tkdkavala.aspida.app

import android.content.Intent
import android.os.Bundle
import android.widget.EditText
import android.widget.Toast
import gr.tkdkavala.aspida.core.BlockList
import gr.tkdkavala.aspida.core.LinkResult
import gr.tkdkavala.aspida.core.Verdict

/**
 * Πύλη συνδέσμων.
 * - Από «άνοιγμα συνδέσμου» (Ασπίδα = προεπιλεγμένος browser): σιωπηλός έλεγχος, αν δεν βρεθεί
 *   γνωστή απειλή ανοίγει αμέσως στον κανονικό browser. Σταματά ΜΟΝΟ σε κίνδυνο/υποψία.
 * - Από «Κοινή χρήση → Έλεγχος με Ασπίδα» ή επιλογή κειμένου: δείχνει το αποτέλεσμα. Δεν ανοίγει τίποτα αυτόματα.
 */
class LinkGateActivity : BaseActivity() {
    private var fromViewIntent = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val i = intent
        val input: String? = when (i?.action) {
            Intent.ACTION_VIEW -> { fromViewIntent = true; i.dataString }
            Intent.ACTION_SEND -> i.getStringExtra(Intent.EXTRA_TEXT)
            Intent.ACTION_PROCESS_TEXT -> i.getCharSequenceExtra(Intent.EXTRA_PROCESS_TEXT)?.toString()
            else -> null
        }
        if (input.isNullOrBlank()) manual() else run(input)
    }

    private fun manual() {
        clear(); header("Έλεγχος συνδέσμου", "Επικόλλησε σύνδεσμο ή ολόκληρο μήνυμα.")
        val e: EditText = input("https://…", null)
        button("Έλεγχος") { e.text.toString().takeIf { it.isNotBlank() }?.let { run(it) } }
        text("Συμβουλή: σε Messenger, Instagram, WhatsApp, Viber πάτα παρατεταμένα τον σύνδεσμο → Κοινή χρήση → «Έλεγχος με Ασπίδα».", C.MUTED, 13f)
    }

    private fun run(input: String) {
        clear(); header("Ασπίδα", "Ελέγχω τον σύνδεσμο…")
        // 1) Ενεργός προσωρινός αποκλεισμός;
        val pre = app.analyzer.parse(app.analyzer.extractUrl(input) ?: input.trim())
        val blocked = pre?.let { app.blockList.activeFor(it.normalized) }
        if (blocked != null) {
            clear(); header("Αποκλεισμένος σύνδεσμος")
            card(C.RED) {
                text("⛔ Ο σύνδεσμος είναι σε προσωρινό αποκλεισμό", C.RED, 19f, this)
                text("Λόγος: ${blocked.reason}\nΠηγή: ${blocked.source}\nΛήγει: ${fmtTime(blocked.expiresAt)} (μετά γίνεται επανέλεγχος)", C.TEXT, 14f, this)
            }
            button("Κλείσιμο") { finish() }
            button("Διαχείριση καραντίνας", C.MUTED, false) { go(QuarantineActivity::class.java) }
            return
        }
        bg {
            val r = app.linkChecker().check(input)
            if (r.verdict == Verdict.DANGEROUS && r.finalUrl != null) {
                val reason = r.findings.filter { it.confirmed }.joinToString { it.message }
                app.blockList.add(r.finalUrl!!, r.host ?: "?", reason, r.servicesChecked.joinToString())
                if (pre != null && pre.normalized != r.finalUrl) app.blockList.add(pre.normalized, pre.unicodeHost, reason, r.servicesChecked.joinToString())
                app.saveBlocks()
                Alerts.notify(this, "⛔ Ασπίδα: αποκλείστηκε επικίνδυνος σύνδεσμος", r.host ?: "")
            }
            // Ληγμένος αποκλεισμός που δεν επιβεβαιώνεται πια ως απειλή → αφαιρείται.
            pre?.let { p ->
                val h = BlockList.hash(p.normalized)
                if (r.verdict != Verdict.DANGEROUS && app.blockList.expired().any { it.urlHash == h }) { app.blockList.recheckDone(h, false); app.saveBlocks() }
            }
            app.history.add("link", r.host ?: "(άκυρο)", r.verdict, r.findings.maxByOrNull { it.weight }?.message ?: "")
            ui { show(r) }
        }
    }

    private fun show(r: LinkResult) {
        val url = r.finalUrl
        // Σιωπηλή λειτουργία: καμία διακοπή όταν δεν βρέθηκε γνωστή απειλή.
        if (fromViewIntent && url != null && r.verdict == Verdict.NO_KNOWN_THREAT) {
            if (Protection.openInBrowser(this, url)) { finish(); return }
        }
        if (fromViewIntent && url != null && r.verdict == Verdict.UNCHECKED && !app.settings.askWhenUnchecked) {
            Toast.makeText(this, "Ασπίδα: δεν ολοκληρώθηκε ο έλεγχος", Toast.LENGTH_SHORT).show()
            if (Protection.openInBrowser(this, url)) { finish(); return }
        }
        clear(); header("Αποτέλεσμα ελέγχου")
        val chain = if (r.redirectChain.size > 1) "Διαδρομή: " + r.redirectChain.joinToString(" → ") { app.analyzer.parse(it)?.unicodeHost ?: it } else null
        val services = buildString {
            if (r.servicesChecked.isNotEmpty()) append("Έλεγχος σε: ${r.servicesChecked.joinToString()}")
            if (r.servicesFailed.isNotEmpty()) { if (isNotEmpty()) append('\n'); append("Δεν ολοκληρώθηκε: ${r.servicesFailed.joinToString()}") }
        }
        verdictCard(r.verdict, r.confidence, r.host ?: r.inputUrl.take(80), r.findings, listOfNotNull(chain, services.ifEmpty { null }).joinToString("\n").ifEmpty { null })

        when (r.verdict) {
            Verdict.NO_KNOWN_THREAT -> {
                if (url != null) button("Άνοιγμα") { if (Protection.openInBrowser(this, url)) finish() else toast("Δεν βρέθηκε browser") }
                button("Κλείσιμο", C.MUTED, false) { finish() }
            }
            Verdict.UNCHECKED -> {
                button("Κλείσιμο (προτείνεται)") { finish() }
                if (url != null) button("Άνοιγμα χωρίς πλήρη έλεγχο", C.BLUE, false) { if (Protection.openInBrowser(this, url)) finish() }
            }
            Verdict.SUSPICIOUS -> {
                button("Μην το ανοίξεις", C.YELLOW) { finish() }
                if (url != null) button("Άνοιγμα με δική μου ευθύνη", C.MUTED, false) {
                    Auth.confirm(this, "Άνοιγμα ύποπτου συνδέσμου") { if (Protection.openInBrowser(this, url)) finish() }
                }
            }
            Verdict.DANGEROUS -> {
                text("Ο σύνδεσμος μπήκε σε προσωρινό αποκλεισμό 7 ημερών. Μετά γίνεται αυτόματος επανέλεγχος.", C.MUTED, 13f)
                button("Κλείσιμο", C.RED) { finish() }
            }
        }
    }
}
