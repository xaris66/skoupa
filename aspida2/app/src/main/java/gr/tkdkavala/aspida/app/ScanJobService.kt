package gr.tkdkavala.aspida.app

import android.app.job.JobInfo
import android.app.job.JobParameters
import android.app.job.JobScheduler
import android.app.job.JobService
import android.content.ComponentName
import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import gr.tkdkavala.aspida.core.Verdict

/**
 * Σιωπηλός έλεγχος του φακέλου Λήψεις (μέσω JobScheduler — χαμηλή κατανάλωση, επιβιώνει επανεκκίνηση).
 * Ελέγχει μόνο ΝΕΑ αρχεία, έως 40 ανά εκτέλεση, έως 300 MB το καθένα. Ειδοποιεί μόνο για κίνδυνο.
 */
class ScanJobService : JobService() {
    @Volatile private var stop = false

    override fun onStartJob(params: JobParameters): Boolean {
        stop = false
        val app = AspidaApp.of(this)
        app.io.execute {
            try { runScan(app) } catch (e: Exception) { /* καμία διαρροή πληροφοριών */ }
            jobFinished(params, false)
        }
        return true
    }

    override fun onStopJob(params: JobParameters): Boolean { stop = true; return true }

    private fun runScan(app: AspidaApp) {
        val s = app.settings
        if (!s.backgroundScan) return
        val tree = s.downloadsTree?.let { Uri.parse(it) } ?: return
        val since = s.lastBgScan
        val started = System.currentTimeMillis()
        val scanner = app.fileScanner()
        val children = DocumentsContract.buildChildDocumentsUriUsingTree(tree, DocumentsContract.getTreeDocumentId(tree))
        val cols = arrayOf(DocumentsContract.Document.COLUMN_DOCUMENT_ID, DocumentsContract.Document.COLUMN_DISPLAY_NAME,
            DocumentsContract.Document.COLUMN_SIZE, DocumentsContract.Document.COLUMN_LAST_MODIFIED, DocumentsContract.Document.COLUMN_MIME_TYPE)
        var n = 0; var bad = 0
        contentResolver.query(children, cols, null, null, null)?.use { c ->
            while (c.moveToNext() && n < 40 && !stop) {
                if (c.getString(4) == DocumentsContract.Document.MIME_TYPE_DIR) continue
                val modified = c.getLong(3); val size = c.getLong(2)
                if (modified <= since || size > 300L * 1024 * 1024) continue
                val uri = DocumentsContract.buildDocumentUriUsingTree(tree, c.getString(0))
                val name = c.getString(1) ?: "αρχείο"
                val r = try { scanner.scan(name, size) { contentResolver.openInputStream(uri) ?: throw java.io.IOException() } } catch (e: Exception) { continue }
                n++
                if (r.verdict == Verdict.DANGEROUS || r.verdict == Verdict.SUSPICIOUS) {
                    bad++
                    app.history.add("bg", name, r.verdict, r.findings.maxByOrNull { it.weight }?.message ?: "")
                    Alerts.notify(this, if (r.verdict == Verdict.DANGEROUS) "⛔ Επικίνδυνο αρχείο στις Λήψεις" else "⚠ Ύποπτο αρχείο στις Λήψεις",
                        "$name — ${r.findings.maxByOrNull { it.weight }?.message ?: ""}\nΆνοιξε την Ασπίδα → Έλεγχος αρχείου για λεπτομέρειες.")
                }
            }
        }
        if (!stop) s.lastBgScan = started
        // Καθαρισμός αποκλεισμών που έληξαν πριν από 30+ ημέρες (δεν κρατάμε δεδομένα χωρίς λόγο).
        val old = app.blockList.expired().filter { it.expiresAt < started - 30L * 86_400_000 }
        if (old.isNotEmpty()) { old.forEach { app.blockList.remove(it.urlHash) }; app.saveBlocks() }
    }

    companion object {
        private const val JOB_ID = 4201
        fun schedule(c: Context) {
            val js = c.getSystemService(JobScheduler::class.java)
            val s = AspidaApp.of(c).settings
            if (!s.backgroundScan || s.downloadsTree == null) { js.cancel(JOB_ID); return }
            if (js.getPendingJob(JOB_ID) != null) return
            js.schedule(JobInfo.Builder(JOB_ID, ComponentName(c, ScanJobService::class.java))
                .setPeriodic(6 * 3600_000L)
                .setRequiresBatteryNotLow(true)
                .setPersisted(true) // επιβιώνει επανεκκίνηση (RECEIVE_BOOT_COMPLETED)
                .build())
        }
    }
}
