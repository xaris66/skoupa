package gr.tkdkavala.aspida.app

import android.Manifest
import android.app.role.RoleManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build

/** Πραγματική κατάσταση προστασίας — ό,τι δείχνει η οθόνη προκύπτει από εδώ, όχι από διακοσμητικά ποσοστά. */
object Protection {
    fun notificationsOk(c: Context) = Build.VERSION.SDK_INT < 33 || c.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED
    fun safeBrowsingOk(c: Context) = !AspidaApp.of(c).settings.safeBrowsingKey.isNullOrBlank()
    fun linkGateOk(c: Context) = c.getSystemService(RoleManager::class.java)?.let { it.isRoleAvailable(RoleManager.ROLE_BROWSER) && it.isRoleHeld(RoleManager.ROLE_BROWSER) } ?: false
    fun downloadsOk(c: Context): Boolean {
        val t = AspidaApp.of(c).settings.downloadsTree ?: return false
        return c.contentResolver.persistedUriPermissions.any { it.uri.toString() == t && it.isReadPermission }
    }
    fun browserOk(c: Context) = realBrowser(c) != null

    data class BrowserApp(val pkg: String, val label: String)

    /** Πραγματικοί browsers στο κινητό (εκτός της Ασπίδας). */
    fun browsers(c: Context): List<BrowserApp> {
        val pm = c.packageManager
        val i = Intent(Intent.ACTION_VIEW, Uri.parse("https://example.com/")).addCategory(Intent.CATEGORY_BROWSABLE)
        return pm.queryIntentActivities(i, PackageManager.MATCH_ALL)
            .map { it.activityInfo.packageName to it.loadLabel(pm).toString() }
            .filter { it.first != c.packageName }.distinctBy { it.first }
            .map { BrowserApp(it.first, it.second) }
    }

    private val preferred = listOf("com.sec.android.app.sbrowser", "com.android.chrome", "org.mozilla.firefox", "com.brave.browser", "com.microsoft.emmx")

    fun realBrowser(c: Context): String? {
        val list = browsers(c).map { it.pkg }
        AspidaApp.of(c).settings.browserPackage?.let { if (it in list) return it }
        return preferred.firstOrNull { it in list } ?: list.firstOrNull()
    }

    /** Ανοίγει το URL στον πραγματικό browser (ποτέ ξανά στην Ασπίδα → χωρίς βρόχο). */
    fun openInBrowser(c: Context, url: String): Boolean {
        val pkg = realBrowser(c) ?: return false
        return try {
            c.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)).addCategory(Intent.CATEGORY_BROWSABLE).setPackage(pkg).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            true
        } catch (e: Exception) { false }
    }
}
