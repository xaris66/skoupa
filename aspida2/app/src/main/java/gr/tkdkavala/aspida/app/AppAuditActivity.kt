package gr.tkdkavala.aspida.app

import android.app.AppOpsManager
import android.app.KeyguardManager
import android.app.admin.DevicePolicyManager
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.provider.Telephony
import java.text.SimpleDateFormat
import java.util.Locale

/**
 * Έλεγχος εφαρμογών & κινητού, όσο επιτρέπει το Android.
 * ΠΟΤΕ δεν χαρακτηρίζει εφαρμογή «κακόβουλη» μόνο από τα δικαιώματα — δείχνει τι μπορεί να κάνει.
 */
class AppAuditActivity : BaseActivity() {
    private val trustedInstallers = setOf("com.android.vending", "com.sec.android.app.samsungapps", "com.google.android.packageinstaller.ignored")

    data class AppRow(val label: String, val pkg: String, val flags: List<String>, val sideloaded: Boolean, val risk: Int)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        header("Ασφάλεια εφαρμογών & κινητού", "Ελέγχω…")
        bg { val d = deviceChecks(); val apps = appChecks(); ui { render(d, apps) } }
    }

    private fun deviceChecks(): List<Triple<String, Boolean?, String>> {
        val out = ArrayList<Triple<String, Boolean?, String>>()
        val km = getSystemService(KeyguardManager::class.java)
        out += Triple("Κλείδωμα οθόνης", km.isDeviceSecure, if (km.isDeviceSecure) "Ενεργό (PIN/μοτίβο/κωδικός)" else "ΔΕΝ υπάρχει κλείδωμα — ρύθμισέ το άμεσα")
        val patch = Build.VERSION.SECURITY_PATCH
        val age = try { (System.currentTimeMillis() - SimpleDateFormat("yyyy-MM-dd", Locale.US).parse(patch)!!.time) / 86_400_000L } catch (e: Exception) { -1 }
        out += Triple("Ενημέρωση ασφαλείας", age in 0..100, "Επίπεδο: $patch" + if (age > 100) " — πάνω από 3 μήνες, έλεγξε για ενημέρωση" else "")
        val dev = Settings.Global.getInt(contentResolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1
        val adb = Settings.Global.getInt(contentResolver, Settings.Global.ADB_ENABLED, 0) == 1
        out += Triple("Επιλογές προγραμματιστή / USB debugging", !adb, when { adb -> "Το USB debugging είναι ΕΝΕΡΓΟ — κλείσ' το αν δεν το χρειάζεσαι"; dev -> "Οι επιλογές προγραμματιστή είναι ενεργές"; else -> "Ανενεργά" })
        val a11y = Settings.Secure.getString(contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES).orEmpty().split(':').filter { it.isNotBlank() }
        out += Triple("Υπηρεσίες προσβασιμότητας", a11y.isEmpty(), if (a11y.isEmpty()) "Καμία ενεργή" else a11y.joinToString("\n") { "• " + labelOf(it.substringBefore('/')) })
        val listeners = Settings.Secure.getString(contentResolver, "enabled_notification_listeners").orEmpty().split(':').filter { it.isNotBlank() }
        out += Triple("Πρόσβαση στις ειδοποιήσεις", null, if (listeners.isEmpty()) "Καμία εφαρμογή" else listeners.joinToString("\n") { "• " + labelOf(it.substringBefore('/')) })
        val dpm = getSystemService(DevicePolicyManager::class.java)
        val admins = dpm.activeAdmins.orEmpty().map { labelOf(it.packageName) }
        out += Triple("Διαχειριστές συσκευής", null, if (admins.isEmpty()) "Κανένας" else admins.joinToString("\n") { "• $it" })
        val sms = Telephony.Sms.getDefaultSmsPackage(this)
        out += Triple("Εφαρμογή SMS", null, sms?.let { labelOf(it) } ?: "—")
        return out
    }

    private fun labelOf(pkg: String) = try { packageManager.getApplicationLabel(packageManager.getApplicationInfo(pkg, 0)).toString() + " ($pkg)" } catch (e: Exception) { pkg }

    @Suppress("DEPRECATION")
    private fun appChecks(): List<AppRow> {
        val pm = packageManager
        val ops = getSystemService(AppOpsManager::class.java)
        val pkgs: List<PackageInfo> = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
        return pkgs.mapNotNull { p ->
            val ai = p.applicationInfo ?: return@mapNotNull null
            val system = (ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0 && (ai.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) == 0
            if (system || p.packageName == packageName) return@mapNotNull null
            val installer = try { pm.getInstallSourceInfo(p.packageName).installingPackageName } catch (e: Exception) { null }
            val sideloaded = installer == null || installer !in trustedInstallers
            val req = p.requestedPermissions.orEmpty()
            val granted = req.filterIndexed { i, _ -> (p.requestedPermissionsFlags?.getOrNull(i) ?: 0) and PackageInfo.REQUESTED_PERMISSION_GRANTED != 0 }.toSet()
            val f = ArrayList<String>(); var risk = 0
            fun has(s: String) = granted.any { it.endsWith(s) }
            if (has("READ_SMS") || has("RECEIVE_SMS")) { f += "SMS"; risk += 2 }
            if (has("READ_CONTACTS")) f += "Επαφές"
            if (has("RECORD_AUDIO")) f += "Μικρόφωνο"
            if (has("CAMERA")) f += "Κάμερα"
            if (has("ACCESS_FINE_LOCATION") || has("ACCESS_BACKGROUND_LOCATION")) f += "Τοποθεσία"
            if (has("READ_CALL_LOG")) { f += "Κλήσεις"; risk += 1 }
            val overlay = try { ops.unsafeCheckOpNoThrow(AppOpsManager.OPSTR_SYSTEM_ALERT_WINDOW, ai.uid, p.packageName) == AppOpsManager.MODE_ALLOWED } catch (e: Exception) { false }
            if (overlay) { f += "Πάνω από άλλες εφαρμογές"; risk += 1 }
            val canInstall = try { ops.unsafeCheckOpNoThrow("android:request_install_packages", ai.uid, p.packageName) == AppOpsManager.MODE_ALLOWED } catch (e: Exception) { false }
            if (canInstall) { f += "Εγκαθιστά εφαρμογές"; risk += 2 }
            if (sideloaded) { f += "Από άγνωστη πηγή"; risk += 2 }
            AppRow(ai.loadLabel(pm).toString(), p.packageName, f, sideloaded, risk)
        }.sortedWith(compareByDescending<AppRow> { it.risk }.thenBy { it.label })
    }

    private fun render(device: List<Triple<String, Boolean?, String>>, apps: List<AppRow>) {
        clear(); header("Ασφάλεια εφαρμογών & κινητού", "Τα δικαιώματα δείχνουν τι ΜΠΟΡΕΙ να κάνει μια εφαρμογή — δεν σημαίνουν ότι είναι κακόβουλη.")
        section("Κινητό")
        device.forEach { (t, ok, d) -> statusRow(t, ok, d) }
        statusRow("Google Play Protect", null, "Δεν ελέγχεται αυτόματα (δεν υπάρχει δημόσιο API). Πάτα για να το ανοίξεις και βεβαιώσου ότι είναι ΕΝΕΡΓΟ.") {
            try { startActivity(Intent("com.google.android.gms.settings.VERIFY_APPS_SETTINGS")) } catch (e: Exception) { startActivity(Intent(Settings.ACTION_SECURITY_SETTINGS)) }
        }
        statusRow("Samsung Auto Blocker", null, "Ρυθμίσεις → Ασφάλεια και απόρρητο → Auto Blocker. Πάτα για να ανοίξεις την Ασφάλεια.") { startActivity(Intent(Settings.ACTION_SECURITY_SETTINGS)) }

        val side = apps.filter { it.sideloaded }
        section("Εφαρμογές από άγνωστη πηγή (${side.size})")
        if (side.isEmpty()) text("Καμία — όλες από Google Play ή Galaxy Store.", C.GREEN)
        side.forEach { row(it) }
        val others = apps.filter { !it.sideloaded && it.risk > 0 }
        section("Με ευαίσθητες άδειες (${others.size})")
        others.forEach { row(it) }
        text("Σύνολο εφαρμογών χρήστη: ${apps.size}", C.MUTED, 12f)
        app.history.add("audit", "Έλεγχος κινητού", gr.tkdkavala.aspida.core.Verdict.NO_KNOWN_THREAT, "${side.size} από άγνωστη πηγή")
    }

    private fun row(a: AppRow) = statusRow(a.label, if (a.risk >= 3) false else null, a.flags.joinToString(" · ").ifEmpty { "—" }) {
        startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:" + a.pkg)))
    }
}
