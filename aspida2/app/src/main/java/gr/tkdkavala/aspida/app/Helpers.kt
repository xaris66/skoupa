package gr.tkdkavala.aspida.app

import android.app.Activity
import android.app.Notification
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.CancellationSignal

object Alerts {
    fun notify(c: Context, title: String, text: String) {
        if (!Protection.notificationsOk(c)) return
        val pi = PendingIntent.getActivity(c, 0, Intent(c, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        val n = Notification.Builder(c, AspidaApp.CH_ALERTS)
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentTitle(title).setContentText(text).setStyle(Notification.BigTextStyle().bigText(text))
            .setContentIntent(pi).setAutoCancel(true).build()
        c.getSystemService(NotificationManager::class.java).notify((System.currentTimeMillis() % 100000).toInt(), n)
    }
}

/** Επιβεβαίωση ταυτότητας (δακτυλικό ή PIN/μοτίβο) πριν από επικίνδυνες ενέργειες. */
object Auth {
    fun confirm(a: Activity, title: String, onOk: () -> Unit) {
        val authenticators = BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL
        val bm = a.getSystemService(BiometricManager::class.java)
        if (bm == null || bm.canAuthenticate(authenticators) != BiometricManager.BIOMETRIC_SUCCESS) {
            // Χωρίς κλείδωμα οθόνης δεν μπορεί να γίνει επιβεβαίωση — ζητάμε ρητή επιβεβαίωση.
            android.app.AlertDialog.Builder(a).setTitle(title)
                .setMessage("Το κινητό δεν έχει ρυθμισμένο κλείδωμα οθόνης, οπότε δεν μπορεί να γίνει επιβεβαίωση ταυτότητας. Συνέχεια;")
                .setPositiveButton("Συνέχεια") { _, _ -> onOk() }.setNegativeButton("Άκυρο", null).show()
            return
        }
        BiometricPrompt.Builder(a).setTitle(title).setSubtitle("Επιβεβαίωσε ότι είσαι εσύ")
            .setAllowedAuthenticators(authenticators).build()
            .authenticate(CancellationSignal(), a.mainExecutor, object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult?) { onOk() }
            })
    }
}
