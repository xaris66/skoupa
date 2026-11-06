package gr.tkdkavala.aspida.app

import android.os.Build

class MainActivity : BaseActivity() {
    override fun onResume() { super.onResume(); render() }

    private fun render() {
        clear()
        val ctx = this
        val sb = Protection.safeBrowsingOk(ctx)
        val gate = Protection.linkGateOk(ctx)
        val notif = Protection.notificationsOk(ctx)
        val dl = Protection.downloadsOk(ctx)
        val core = sb && notif
        header("Ασπίδα 2", if (core) "Η βασική προστασία είναι ενεργή." else "Η προστασία δεν έχει ολοκληρωθεί.")

        button(if (app.settings.setupDone && core) "ΡΥΘΜΙΣΕΙΣ ΠΡΟΣΤΑΣΙΑΣ" else "ΕΝΕΡΓΟΠΟΙΗΣΗ ΠΡΟΣΤΑΣΙΑΣ", if (core) C.GREEN else C.YELLOW) { go(SetupActivity::class.java) }

        section("Πραγματική κατάσταση")
        statusRow("Έλεγχος συνδέσμων (Google)", sb, if (sb) "Google Safe Browsing v5 ρυθμισμένο" else "Λείπει το κλειδί — οι έλεγχοι θα λένε «Δεν ολοκληρώθηκε»") { go(SetupActivity::class.java) }
        statusRow("Πύλη συνδέσμων", gate, if (gate) "Κάθε σύνδεσμος που πατάς περνά πρώτα από την Ασπίδα" else "Προαιρετικό — ορίζεται ως προεπιλεγμένος browser") { go(SetupActivity::class.java) }
        statusRow("Έλεγχος Λήψεων στο παρασκήνιο", dl && app.settings.backgroundScan, if (dl) "Τελευταίος έλεγχος: " + (app.settings.lastBgScan.takeIf { it > 0 }?.let { fmtTime(it) } ?: "δεν έχει τρέξει ακόμα") else "Δεν έχει δοθεί πρόσβαση στον φάκελο Λήψεις") { go(SetupActivity::class.java) }
        statusRow("Ειδοποιήσεις", notif, if (notif) "Επιτρέπονται" else "Χωρίς αυτές δεν σε ειδοποιεί για κινδύνους") { go(SetupActivity::class.java) }
        statusRow("Φίλτρο δικτύου", null, "Σε ανάπτυξη — ΔΕΝ είναι ενεργό. Δες «Προστασία δικτύου».") { go(NetworkActivity::class.java) }
        val blocks = app.blockList.all().size
        if (blocks > 0) statusRow("Προσωρινοί αποκλεισμοί", true, "$blocks ενεργοί/προς επανέλεγχο") { go(QuarantineActivity::class.java) }

        section("Εργαλεία")
        button("Έλεγχος συνδέσμου", C.GREEN, false) { go(LinkGateActivity::class.java) }
        button("Έλεγχος αρχείου", C.GREEN, false) { go(FileCheckActivity::class.java) }
        button("Ασφάλεια εφαρμογών & κινητού", C.GREEN, false) { go(AppAuditActivity::class.java) }
        button("Facebook / Instagram / Messenger", C.GREEN, false) { go(AccountsActivity::class.java) }
        button("Προστασία δικτύου", C.GREEN, false) { go(NetworkActivity::class.java) }
        button("Καραντίνα", C.GREEN, false) { go(QuarantineActivity::class.java) }
        button("Ιστορικό", C.GREEN, false) { go(HistoryActivity::class.java) }
        button("Ρυθμίσεις", C.MUTED, false) { go(SettingsActivity::class.java) }
        text("Έκδοση ${packageManager.getPackageInfo(packageName, 0).versionName} · Android ${Build.VERSION.RELEASE}", C.MUTED, 12f)
    }
}
