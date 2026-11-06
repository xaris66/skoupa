package gr.tkdkavala.aspida.app

import android.app.AlertDialog
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Uri
import android.os.Bundle
import android.provider.Settings as AndroidSettings
import android.widget.Switch

/** Facebook / Instagram / Messenger / WhatsApp: τι κάνει πραγματικά η Ασπίδα και οδηγός λογαριασμών. */
class AccountsActivity : BaseActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        header("Facebook · Instagram · Messenger · WhatsApp", "Χρησιμοποιείς τις εφαρμογές κανονικά. Η Ασπίδα ΔΕΝ διαβάζει τα μηνύματά σου.")
        section("Πώς ελέγχεις έναν σύνδεσμο")
        card {
            text("1. Πάτα παρατεταμένα τον σύνδεσμο στη συνομιλία.", C.TEXT, 15f, this)
            text("2. Κοινή χρήση → «Έλεγχος με Ασπίδα».", C.TEXT, 15f, this)
            text("Facebook και Instagram ανοίγουν τους συνδέσμους στον δικό τους browser, οπότε εκεί η Πύλη δεν τους «βλέπει». Γι' αυτό: είτε Κοινή χρήση στην Ασπίδα, είτε «Άνοιγμα σε εξωτερικό πρόγραμμα περιήγησης» από το μενού ⋮.", C.MUTED, 13f, this)
            text("WhatsApp, Viber, SMS και email ανοίγουν τους συνδέσμους στον προεπιλεγμένο browser, άρα περνούν από την Πύλη αν είναι ενεργή.", C.MUTED, 13f, this)
        }
        section("Θωράκιση λογαριασμών (επίσημες σελίδες)")
        link("Meta: κωδικός, έλεγχος ταυτότητας 2 παραγόντων, passkeys", "https://accountscenter.facebook.com/password_and_security")
        link("Meta: πού είσαι συνδεδεμένος (αποσύνδεση άγνωστων συσκευών)", "https://accountscenter.facebook.com/password_and_security/login_activity")
        link("Instagram: κωδικός & ασφάλεια", "https://accountscenter.instagram.com/password_and_security")
        link("WhatsApp: επαλήθευση δύο βημάτων", "https://faq.whatsapp.com/1920866721452534")
        link("Google: έλεγχος ασφαλείας λογαριασμού", "https://myaccount.google.com/security-checkup")
        card {
            text("Τι να ενεργοποιήσεις:", C.TEXT, 15f, this)
            text("• Passkey ή εφαρμογή επαλήθευσης (όχι μόνο SMS)\n• Ειδοποιήσεις για άγνωστες συνδέσεις\n• Αποσύνδεση από συσκευές που δεν αναγνωρίζεις\n• Ποτέ μη δίνεις κωδικό που ήρθε με SMS σε κανέναν, ούτε σε «φίλο» στο Messenger", C.MUTED, 14f, this)
        }
        text("Η Ασπίδα δεν μπορεί να εγγυηθεί ότι δεν θα παραβιαστεί ποτέ ένας λογαριασμός. Μειώνει τον κίνδυνο από ψεύτικους συνδέσμους.", C.MUTED, 12f)
    }
    private fun link(t: String, url: String) = button(t, C.GREEN, false) { Protection.openInBrowser(this, url) || run { startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url))); true } }
}

/** Προστασία δικτύου: ειλικρινής κατάσταση. Το φίλτρο VPN δεν δηλώνεται ενεργό πριν περάσει δοκιμές. */
class NetworkActivity : BaseActivity() {
    override fun onResume() {
        super.onResume(); clear()
        header("Προστασία δικτύου")
        val cm = getSystemService(ConnectivityManager::class.java)
        val lp = cm.getLinkProperties(cm.activeNetwork)
        val pdnsActive = lp?.isPrivateDnsActive == true
        val pdnsName = lp?.privateDnsServerName
        statusRow("Ιδιωτικό DNS", if (pdnsName != null) true else if (pdnsActive) null else false,
            when { pdnsName != null -> "Ενεργό: $pdnsName"; pdnsActive -> "Αυτόματο (κρυπτογραφημένο, χωρίς φίλτρο)"; else -> "Ανενεργό" })
        statusRow("Φίλτρο δικτύου Ασπίδας (VpnService)", null, "ΣΕ ΑΝΑΠΤΥΞΗ — δεν είναι ενεργό. Θα ενεργοποιηθεί μόνο αφού περάσει δοκιμές σε Wi-Fi και δεδομένα κινητής.")
        section("Άμεση λύση χωρίς μπαταρία")
        card {
            text("Ρύθμισε «Ιδιωτικό DNS» σε πάροχο που μπλοκάρει γνωστές κακόβουλες διευθύνσεις για ΟΛΟ το κινητό (Wi-Fi και 5G):", C.TEXT, 15f, this)
            text("security.cloudflare-dns.com", C.GREEN, 17f, this)
            text("Ρυθμίσεις → Συνδέσεις → Περισσότερες ρυθμίσεις σύνδεσης → Ιδιωτικό DNS → «Όνομα κεντρικού υπολογιστή παρόχου».\nΔεν αποκρυπτογραφεί HTTPS και δεν χρειάζεται VPN, άρα δεν συγκρούεται με άλλο VPN.", C.MUTED, 13f, this)
        }
        button("Αντιγραφή ονόματος") {
            getSystemService(android.content.ClipboardManager::class.java).setPrimaryClip(android.content.ClipData.newPlainText("dns", "security.cloudflare-dns.com")); toast("Αντιγράφηκε")
        }
        button("Άνοιγμα ρυθμίσεων σύνδεσης", C.GREEN, false) { startActivity(Intent(AndroidSettings.ACTION_WIRELESS_SETTINGS)) }
        text("Σημείωση: στο Android μπορεί να είναι ενεργό μόνο ένα VPN τη φορά.", C.MUTED, 12f)
    }
}

class QuarantineActivity : BaseActivity() {
    override fun onResume() {
        super.onResume(); clear()
        header("Καραντίνα", "Προσωρινοί αποκλεισμοί με λήξη. Τίποτα δεν διαγράφεται αυτόματα.")
        val now = System.currentTimeMillis()
        section("Σύνδεσμοι")
        val list = app.blockList.all()
        if (list.isEmpty()) text("Κανένας αποκλεισμός.", C.MUTED)
        list.forEach { e ->
            val active = e.expiresAt > now
            statusRow(e.displayHost, if (active) false else null,
                "${e.reason}\nΠηγή: ${e.source} · ${if (active) "λήγει ${fmtTime(e.expiresAt)}" else "έληξε — θα ξαναελεγχθεί στο επόμενο άνοιγμα"}") {
                AlertDialog.Builder(this).setTitle("Αφαίρεση αποκλεισμού;").setMessage("Μόνο αν είσαι σίγουρος ότι ήταν λάθος.")
                    .setPositiveButton("Αφαίρεση") { _, _ -> Auth.confirm(this, "Αφαίρεση αποκλεισμού") { app.blockList.remove(e.urlHash); app.saveBlocks(); onResume() } }
                    .setNegativeButton("Άκυρο", null).show()
            }
        }
        section("Αρχεία")
        val files = app.quarantineDir.listFiles().orEmpty().sortedByDescending { it.lastModified() }
        if (files.isEmpty()) text("Κανένα αρχείο.", C.MUTED)
        files.forEach { f ->
            statusRow(f.name.substringAfter('_'), false, "Σε καραντίνα από ${fmtTime(f.lastModified())} · %.1f MB".format(f.length() / 1048576.0)) {
                AlertDialog.Builder(this).setTitle("Οριστική διαγραφή;").setMessage(f.name.substringAfter('_'))
                    .setPositiveButton("Διαγραφή") { _, _ -> Auth.confirm(this, "Διαγραφή αρχείου") { f.delete(); onResume() } }
                    .setNegativeButton("Άκυρο", null).show()
            }
        }
    }
}

class HistoryActivity : BaseActivity() {
    override fun onResume() {
        super.onResume(); clear()
        header("Ιστορικό", "Κρατάω μόνο όνομα ιστοσελίδας/αρχείου και αποτέλεσμα — όχι πλήρεις συνδέσμους.")
        val items = app.history.all()
        if (items.isEmpty()) text("Κενό.", C.MUTED)
        items.take(150).forEach { i ->
            card(C.of(i.verdict)) {
                text("${fmtTime(i.time)} · " + when (i.kind) { "link" -> "Σύνδεσμος"; "file" -> "Αρχείο"; "bg" -> "Παρασκήνιο"; else -> "Έλεγχος" }, C.MUTED, 12f, this)
                text(i.subject, C.TEXT, 15f, this)
                text(i.verdict.title + if (i.note.isNotBlank()) " — ${i.note}" else "", C.of(i.verdict), 13f, this)
            }
        }
        if (items.isNotEmpty()) button("Διαγραφή ιστορικού", C.MUTED, false) { app.history.clear(); onResume() }
    }
}

class SettingsActivity : BaseActivity() {
    override fun onResume() {
        super.onResume(); clear()
        val s = app.settings
        header("Ρυθμίσεις")
        section("Κλειδιά (αποθηκεύονται κρυπτογραφημένα)")
        text("Google Safe Browsing API key", C.MUTED, 13f)
        val gsb = input("API key", s.safeBrowsingKey, secret = true)
        text("abuse.ch Auth-Key (προαιρετικό: URLhaus + MalwareBazaar)", C.MUTED, 13f)
        val ab = input("Auth-Key", s.abuseChKey, secret = true)
        button("Αποθήκευση κλειδιών") { s.safeBrowsingKey = gsb.text.toString().ifBlank { null }; s.abuseChKey = ab.text.toString().ifBlank { null }; toast("Αποθηκεύτηκαν") }

        section("Συμπεριφορά")
        toggle("Ακολούθηση ανακατευθύνσεων", "Βρίσκει πού καταλήγει πραγματικά ένας σύνδεσμος (μόνο κεφαλίδες, έως 6 βήματα).", s.followRedirects) { s.followRedirects = it }
        toggle("Ερώτηση όταν δεν ολοκληρώνεται ο έλεγχος", "Κλειστό = ανοίγει με ειδοποίηση «Δεν ολοκληρώθηκε ο έλεγχος».", s.askWhenUnchecked) { s.askWhenUnchecked = it }
        toggle("Έλεγχος Λήψεων στο παρασκήνιο", "Περίπου κάθε 6 ώρες, μόνο νέα αρχεία.", s.backgroundScan) { s.backgroundScan = it; ScanJobService.schedule(this) }

        section("Browser για άνοιγμα συνδέσμων")
        val bs = Protection.browsers(this)
        val cur = Protection.realBrowser(this)
        bs.forEach { b -> button((if (b.pkg == cur) "✓ " else "") + b.label, if (b.pkg == cur) C.GREEN else C.MUTED, b.pkg == cur) { s.browserPackage = b.pkg; onResume() } }
        if (bs.isEmpty()) text("Δεν βρέθηκε browser.", C.YELLOW)
    }

    private fun toggle(t: String, d: String, v: Boolean, set: (Boolean) -> Unit) {
        card {
            val sw = Switch(this@SettingsActivity).apply { text = t; isChecked = v; setTextColor(C.TEXT); textSize = 16f; setOnCheckedChangeListener { _, c -> set(c) } }
            addView(sw); text(d, C.MUTED, 13f, this)
        }
    }
}
