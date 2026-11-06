package gr.tkdkavala.aspida.app

import android.content.Intent
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Bundle
import android.provider.OpenableColumns
import gr.tkdkavala.aspida.core.Confidence
import gr.tkdkavala.aspida.core.FileResult
import gr.tkdkavala.aspida.core.Finding
import gr.tkdkavala.aspida.core.Verdict
import java.io.File

/** Έλεγχος αρχείου: δεν εκτελεί, δεν ανεβάζει, δεν διαγράφει τίποτα αυτόματα. */
class FileCheckActivity : BaseActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        @Suppress("DEPRECATION")
        val uri: Uri? = when (intent?.action) {
            Intent.ACTION_SEND -> intent.getParcelableExtra(Intent.EXTRA_STREAM)
            Intent.ACTION_VIEW -> intent.data
            else -> null
        }
        if (uri != null) scan(uri) else pick()
    }

    private fun pick() {
        clear(); header("Έλεγχος αρχείου", "APK, PDF, ZIP, έγγραφα, φωτογραφίες. Ο έλεγχος γίνεται μέσα στο κινητό.")
        button("Επιλογή αρχείου") {
            startActivityForResult(Intent(Intent.ACTION_OPEN_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType("*/*"), REQ_PICK)
        }
        text("Το αρχείο δεν ανεβαίνει πουθενά. Αν έχεις ορίσει κλειδί abuse.ch, στέλνεται ΜΟΝΟ το αποτύπωμα SHA-256 για σύγκριση με γνωστό κακόβουλο λογισμικό.", C.MUTED, 13f)
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQ_PICK && resultCode == RESULT_OK) data?.data?.let { scan(it) }
    }

    private fun scan(uri: Uri) {
        clear(); header("Ασπίδα", "Ελέγχω το αρχείο…")
        bg {
            var name = "αρχείο"; var size = -1L
            contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE), null, null, null)?.use { c ->
                if (c.moveToFirst()) { name = c.getString(0) ?: name; size = if (c.isNull(1)) -1 else c.getLong(1) }
            }
            var r = app.fileScanner().scan(name, size) { contentResolver.openInputStream(uri) ?: throw java.io.IOException("Δεν ανοίγει") }
            if (r.detectedType == "apk") r = r.copy(findings = r.findings + apkFindings(uri))
            val extra = r.findings.filter { !it.confirmed }.maxOfOrNull { it.weight } ?: 0
            if (r.verdict == Verdict.NO_KNOWN_THREAT && extra >= 50) r = r.copy(verdict = Verdict.SUSPICIOUS, confidence = Confidence.LOW)
            app.history.add("file", r.name, r.verdict, r.findings.maxByOrNull { it.weight }?.message ?: r.detectedType)
            if (r.verdict == Verdict.DANGEROUS) Alerts.notify(this, "⛔ Ασπίδα: επικίνδυνο αρχείο", r.name)
            ui { show(r, uri) }
        }
    }

    /** Για APK: τι δικαιώματα ζητά (μέσω PackageManager, χωρίς εγκατάσταση). */
    private fun apkFindings(uri: Uri): List<Finding> {
        val tmp = File(cacheDir, "check.apk")
        return try {
            contentResolver.openInputStream(uri)?.use { i -> tmp.outputStream().use { i.copyTo(it) } }
            val pi: PackageInfo = packageManager.getPackageArchiveInfo(tmp.path, PackageManager.GET_PERMISSIONS or PackageManager.GET_SERVICES)
                ?: return listOf(Finding("apk-bad", "Το APK δεν μπορεί να διαβαστεί από το Android (κατεστραμμένο ή τροποποιημένο).", weight = 50))
            val perms = pi.requestedPermissions?.toSet().orEmpty()
            val f = ArrayList<Finding>()
            f += Finding("apk-info", "Πακέτο: ${pi.packageName} · έκδοση ${pi.versionName ?: "?"} · ζητά ${perms.size} δικαιώματα.", weight = 0)
            val sms = perms.any { it.endsWith("READ_SMS") || it.endsWith("RECEIVE_SMS") || it.endsWith("SEND_SMS") }
            val a11y = pi.services?.any { it.permission == "android.permission.BIND_ACCESSIBILITY_SERVICE" } == true
            val notif = pi.services?.any { it.permission == "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE" } == true
            val overlay = perms.any { it.endsWith("SYSTEM_ALERT_WINDOW") }
            val install = perms.any { it.endsWith("REQUEST_INSTALL_PACKAGES") }
            val admin = pi.services?.any { it.permission == "android.permission.BIND_DEVICE_ADMIN" } == true
            if (sms) f += Finding("apk-sms", "Ζητά πρόσβαση στα SMS (εκεί έρχονται κωδικοί τραπεζών).", weight = 30)
            if (a11y) f += Finding("apk-a11y", "Περιέχει υπηρεσία προσβασιμότητας — μπορεί να διαβάζει την οθόνη και να πατά κουμπιά.", weight = 35)
            if (notif) f += Finding("apk-notif", "Μπορεί να διαβάζει τις ειδοποιήσεις σου.", weight = 25)
            if (overlay) f += Finding("apk-overlay", "Μπορεί να εμφανίζεται πάνω από άλλες εφαρμογές.", weight = 20)
            if (install) f += Finding("apk-install", "Μπορεί να εγκαθιστά άλλες εφαρμογές.", weight = 20)
            // Συνδυασμός τυπικός για τραπεζικά trojans — υποψία, όχι καταδίκη.
            if (a11y && (sms || overlay || notif)) f += Finding("apk-combo", "Συνδυασμός δικαιωμάτων που χρησιμοποιούν συχνά τα τραπεζικά trojans (προσβασιμότητα + SMS/ειδοποιήσεις/επικάλυψη). Εγκατάστησε ΜΟΝΟ αν ξέρεις ακριβώς τι είναι.", weight = 60)
            if (admin) f += Finding("apk-admin", "Ζητά δικαιώματα διαχειριστή συσκευής.", weight = 40)
            f
        } catch (e: Exception) { emptyList() } finally { tmp.delete() }
    }

    private fun show(r: FileResult, uri: Uri) {
        clear(); header("Αποτέλεσμα ελέγχου")
        verdictCard(r.verdict, r.confidence, r.name, r.findings + Finding("type", "Πραγματικός τύπος: ${app.fileScanner().typeTitle(r.detectedType)}", weight = 1),
            "SHA-256: ${r.sha256.take(16)}…\nΜέγεθος: ${if (r.size >= 0) "%.1f MB".format(r.size / 1048576.0) else "άγνωστο"}")
        if (r.verdict == Verdict.DANGEROUS || r.verdict == Verdict.SUSPICIOUS) {
            button("Μετακίνηση σε καραντίνα", C.YELLOW) {
                Auth.confirm(this, "Καραντίνα αρχείου") {
                    bg {
                        val dst = File(app.quarantineDir, System.currentTimeMillis().toString() + "_" + r.name.replace(Regex("[^\\p{L}\\p{N}._-]"), "_"))
                        contentResolver.openInputStream(uri)?.use { i -> dst.outputStream().use { i.copyTo(it) } }
                        dst.setExecutable(false)
                        // Ο χρήστης το ζήτησε ρητά και επιβεβαίωσε ταυτότητα: προσπάθεια αφαίρεσης του αρχικού.
                        val removed = try { android.provider.DocumentsContract.deleteDocument(contentResolver, uri) } catch (e: Exception) { false }
                        ui { toast(if (removed) "✓ Μεταφέρθηκε σε καραντίνα." else "Αντίγραφο σε καραντίνα. Το αρχικό δεν μπορεί να σβηστεί από εδώ — σβήσ' το από τα «Αρχεία μου».") }
                    }
                }
            }
        }
        button("Έλεγχος άλλου αρχείου", C.GREEN, false) { pick() }
        button("Κλείσιμο", C.MUTED, false) { finish() }
    }

    companion object { const val REQ_PICK = 10 }
}
