package gr.tkdkavala.aspida.app

import android.Manifest
import android.app.AlertDialog
import android.app.role.RoleManager
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.DocumentsContract
import android.widget.EditText

/**
 * Οδηγός «ΕΝΕΡΓΟΠΟΙΗΣΗ ΠΡΟΣΤΑΣΙΑΣ»: ελέγχει τι λείπει, ανοίγει ΜΟΝΟ την επίσημη οθόνη Android,
 * επιβεβαιώνει την έγκριση και προχωρά μόνος του στο επόμενο βήμα. Δεν παρακάμπτει τίποτα.
 */
class SetupActivity : BaseActivity() {
    private data class Step(val title: String, val why: String, val required: Boolean, val done: () -> Boolean, val action: () -> Unit)

    private val skipped = HashSet<String>()
    private var autoAdvance = false

    private val steps by lazy {
        listOf(
            Step("Ειδοποιήσεις", "Για να σε ειδοποιεί μόνο όταν βρει κίνδυνο.", true, { Protection.notificationsOk(this) }) {
                if (Build.VERSION.SDK_INT >= 33) requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), REQ_NOTIF)
            },
            Step("Κλειδί Google Safe Browsing", "Η βάση απειλών της Google. Δωρεάν κλειδί από Google Cloud Console → APIs → «Safe Browsing API» → Credentials → API key.", true, { Protection.safeBrowsingOk(this) }) { askKey() },
            Step("Πραγματικός browser", "Εκεί ανοίγουν οι σύνδεσμοι μετά τον έλεγχο.", true, { Protection.browserOk(this) }) {
                try { startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("market://details?id=com.sec.android.app.sbrowser"))) } catch (e: Exception) { toast("Εγκατάστησε έναν browser (π.χ. Samsung Internet).") }
            },
            Step("Πύλη συνδέσμων (προτείνεται)", "Ορίζεις την Ασπίδα ως «προεπιλεγμένο πρόγραμμα περιήγησης». Κάθε σύνδεσμος που πατάς σε SMS, email, Viber, WhatsApp ελέγχεται σιωπηλά και ανοίγει στον κανονικό σου browser. Θα σε σταματήσει μόνο αν βρει κίνδυνο.", false, { Protection.linkGateOk(this) }) {
                val rm = getSystemService(RoleManager::class.java)
                if (rm != null && rm.isRoleAvailable(RoleManager.ROLE_BROWSER)) startActivityForResult(rm.createRequestRoleIntent(RoleManager.ROLE_BROWSER), REQ_ROLE)
                else startActivity(Intent(android.provider.Settings.ACTION_MANAGE_DEFAULT_APPS_SETTINGS))
            },
            Step("Φάκελος Λήψεις (προτείνεται)", "Ελέγχει στο παρασκήνιο τα νέα αρχεία που κατεβάζεις. Στην επόμενη οθόνη πάτα «Χρήση αυτού του φακέλου» → «Επιτρέπεται».", false, { Protection.downloadsOk(this) }) {
                val i = Intent(Intent.ACTION_OPEN_DOCUMENT_TREE)
                i.putExtra(DocumentsContract.EXTRA_INITIAL_URI, Uri.parse("content://com.android.externalstorage.documents/document/primary%3ADownload"))
                startActivityForResult(i, REQ_TREE)
            },
        )
    }

    override fun onCreate(savedInstanceState: Bundle?) { super.onCreate(savedInstanceState); autoAdvance = true }
    override fun onResume() { super.onResume(); render() }

    private fun render() {
        clear()
        header("Ενεργοποίηση προστασίας", "Ένα βήμα τη φορά. Όπου χρειάζεται, πατάς «Επιτρέπεται».")
        var next: Step? = null
        steps.forEachIndexed { idx, s ->
            val ok = s.done()
            val label = "${idx + 1}. ${s.title}"
            val detail = when { ok -> "✓ Ολοκληρώθηκε"; s.title in skipped -> "Παραλείφθηκε"; else -> s.why }
            statusRow(label, if (ok) true else if (s.required) false else null, detail) { s.action() }
            if (!ok && next == null && s.title !in skipped) next = s
        }
        val n = next
        if (n == null) {
            app.settings.setupDone = true
            ScanJobService.schedule(this)
            space(8)
            text(if (steps.filter { it.required }.all { it.done() }) "✓ Η προστασία είναι ενεργή." else "Λείπουν απαραίτητα βήματα.", C.GREEN, 18f)
            button("Τέλος") { finish() }
        } else {
            space(8)
            button("Συνέχεια: ${n.title}") { n.action() }
            if (!n.required) button("Παράλειψη", C.MUTED, false) { skipped += n.title; render() }
            // Αυτόματη συνέχεια στο επόμενο βήμα μόλις επιστρέψει ο χρήστης από την οθόνη του Android.
            if (autoAdvance && n.required && n.title != "Κλειδί Google Safe Browsing") { autoAdvance = false; n.action() }
        }
    }

    private fun askKey() {
        val e = EditText(this).apply { hint = "Επικόλλησε εδώ το API key"; setText(app.settings.safeBrowsingKey ?: "") }
        AlertDialog.Builder(this).setTitle("Κλειδί Google Safe Browsing").setView(e)
            .setMessage("Αποθηκεύεται κρυπτογραφημένο με το Android Keystore. Θα γίνει δοκιμαστικός έλεγχος.")
            .setPositiveButton("Αποθήκευση") { _, _ -> verifyKey(e.text.toString().trim()) }
            .setNeutralButton("Πώς το βγάζω;") { _, _ -> startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com"))) }
            .setNegativeButton("Άκυρο", null).show()
    }

    private fun verifyKey(k: String) {
        if (k.isEmpty()) return
        toast("Δοκιμή κλειδιού…")
        bg {
            val ok = try {
                val r = app.http.request("GET", "https://safebrowsing.googleapis.com/v5/urls:search?urls=" + Uri.encode("https://www.google.com/") + "&key=" + Uri.encode(k))
                r.code
            } catch (e: Exception) { -1 }
            ui {
                when (ok) {
                    200 -> { app.settings.safeBrowsingKey = k; toast("✓ Το κλειδί λειτουργεί."); render() }
                    -1 -> { app.settings.safeBrowsingKey = k; toast("Αποθηκεύτηκε, αλλά δεν υπάρχει σύνδεση για δοκιμή."); render() }
                    else -> toast("Το κλειδί απορρίφθηκε από την Google (κωδικός $ok). Έλεγξε ότι ενεργοποίησες το Safe Browsing API.")
                }
            }
        }
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQ_TREE && resultCode == RESULT_OK && data?.data != null) {
            val uri = data.data!!
            contentResolver.takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION)
            app.settings.downloadsTree = uri.toString()
            ScanJobService.schedule(this)
        }
        autoAdvance = true
    }

    @Deprecated("Deprecated in Java")
    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == REQ_NOTIF && !Protection.notificationsOk(this)) {
            // Άρνηση: δεν κολλάμε σε βρόχο — προσφέρουμε τις ρυθμίσεις της εφαρμογής.
            toast("Χωρίς ειδοποιήσεις η Ασπίδα δουλεύει, αλλά δεν θα σε ειδοποιεί στο παρασκήνιο.")
            skipped += "Ειδοποιήσεις"
        }
        autoAdvance = true; render()
    }

    companion object { const val REQ_NOTIF = 1; const val REQ_ROLE = 2; const val REQ_TREE = 3 }
}
