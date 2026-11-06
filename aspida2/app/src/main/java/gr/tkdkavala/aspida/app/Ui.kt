package gr.tkdkavala.aspida.app

import android.app.Activity
import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.InputType
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.widget.*
import gr.tkdkavala.aspida.core.Confidence
import gr.tkdkavala.aspida.core.Finding
import gr.tkdkavala.aspida.core.Verdict
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

object C {
    val BG = Color.parseColor("#0B1016")
    val CARD = Color.parseColor("#141C26")
    val TEXT = Color.parseColor("#E8EEF4")
    val MUTED = Color.parseColor("#8FA0B3")
    val GREEN = Color.parseColor("#3DDC97")
    val YELLOW = Color.parseColor("#F5C451")
    val RED = Color.parseColor("#FF5C5C")
    val BLUE = Color.parseColor("#5CA8FF")
    fun of(v: Verdict) = when (v) { Verdict.NO_KNOWN_THREAT -> GREEN; Verdict.SUSPICIOUS -> YELLOW; Verdict.DANGEROUS -> RED; Verdict.UNCHECKED -> BLUE }
}

/** Βάση για όλες τις οθόνες: απλό, γρήγορο UI χωρίς βιβλιοθήκες. */
abstract class BaseActivity : Activity() {
    protected lateinit var root: LinearLayout
    protected val app get() = AspidaApp.of(this)
    private val main = Handler(Looper.getMainLooper())

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val scroll = ScrollView(this).apply { setBackgroundColor(C.BG); isFillViewport = true }
        root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(dp(18), dp(22), dp(18), dp(28)) }
        scroll.addView(root)
        setContentView(scroll)
    }

    fun dp(v: Int) = TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, v.toFloat(), resources.displayMetrics).toInt()
    fun ui(block: () -> Unit) = main.post { if (!isFinishing && !isDestroyed) block() }
    fun bg(work: () -> Unit) = app.io.execute { try { work() } catch (e: Exception) { ui { toast("Σφάλμα: ${e.javaClass.simpleName}") } } }
    fun toast(s: String) = Toast.makeText(this, s, Toast.LENGTH_LONG).show()
    fun clear() = root.removeAllViews()

    fun header(title: String, subtitle: String? = null) {
        root.addView(TextView(this).apply { text = title; setTextColor(C.TEXT); textSize = 26f; typeface = Typeface.DEFAULT_BOLD })
        if (subtitle != null) root.addView(TextView(this).apply { text = subtitle; setTextColor(C.MUTED); textSize = 14f; setPadding(0, dp(4), 0, dp(14)) })
        else space(12)
    }
    fun section(t: String) = root.addView(TextView(this).apply { text = t; setTextColor(C.MUTED); textSize = 13f; typeface = Typeface.DEFAULT_BOLD; setPadding(0, dp(18), 0, dp(6)); isAllCaps = true })
    fun text(t: String, color: Int = C.TEXT, size: Float = 15f, parent: LinearLayout = root): TextView =
        TextView(this).apply { text = t; setTextColor(color); textSize = size; setLineSpacing(0f, 1.15f); setPadding(0, dp(3), 0, dp(3)); setTextIsSelectable(false) }.also { parent.addView(it) }
    fun space(h: Int) = root.addView(View(this), LinearLayout.LayoutParams(1, dp(h)))

    fun card(accent: Int? = null, parent: LinearLayout = root, build: LinearLayout.() -> Unit): LinearLayout {
        val c = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL; setPadding(dp(16), dp(14), dp(16), dp(14))
            background = GradientDrawable().apply { setColor(C.CARD); cornerRadius = dp(14).toFloat(); if (accent != null) setStroke(dp(2), accent) }
        }
        c.build()
        parent.addView(c, LinearLayout.LayoutParams(-1, -2).apply { bottomMargin = dp(10) })
        return c
    }

    fun button(label: String, color: Int = C.GREEN, filled: Boolean = true, parent: LinearLayout = root, onClick: () -> Unit): Button {
        val b = Button(this).apply {
            text = label; isAllCaps = false; textSize = 16f; typeface = Typeface.DEFAULT_BOLD
            setTextColor(if (filled) C.BG else color); minHeight = dp(52)
            background = GradientDrawable().apply { setColor(if (filled) color else Color.TRANSPARENT); cornerRadius = dp(12).toFloat(); setStroke(dp(2), color) }
            setOnClickListener { onClick() }
        }
        parent.addView(b, LinearLayout.LayoutParams(-1, -2).apply { bottomMargin = dp(8) })
        return b
    }

    fun statusRow(label: String, ok: Boolean?, detail: String, parent: LinearLayout = root, onClick: (() -> Unit)? = null) {
        card(parent = parent) {
            val row = LinearLayout(this@BaseActivity).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL }
            row.addView(TextView(this@BaseActivity).apply {
                text = when (ok) { true -> "●"; false -> "●"; null -> "○" }; textSize = 18f
                setTextColor(when (ok) { true -> C.GREEN; false -> C.YELLOW; null -> C.MUTED }); setPadding(0, 0, dp(12), 0)
            })
            val col = LinearLayout(this@BaseActivity).apply { orientation = LinearLayout.VERTICAL }
            col.addView(TextView(this@BaseActivity).apply { text = label; setTextColor(C.TEXT); textSize = 16f; typeface = Typeface.DEFAULT_BOLD })
            col.addView(TextView(this@BaseActivity).apply { text = detail; setTextColor(C.MUTED); textSize = 13f })
            row.addView(col, LinearLayout.LayoutParams(0, -2, 1f))
            addView(row)
            if (onClick != null) { isClickable = true; setOnClickListener { onClick() } }
        }
    }

    fun verdictCard(v: Verdict, conf: Confidence, subject: String, findings: List<Finding>, extra: String? = null) {
        card(C.of(v)) {
            text(when (v) { Verdict.NO_KNOWN_THREAT -> "✓ "; Verdict.SUSPICIOUS -> "⚠ "; Verdict.DANGEROUS -> "⛔ "; Verdict.UNCHECKED -> "? " } + v.title, C.of(v), 20f, this).typeface = Typeface.DEFAULT_BOLD
            text(subject, C.TEXT, 15f, this)
            text("Βεβαιότητα: ${conf.title}", C.MUTED, 13f, this)
            if (extra != null) text(extra, C.MUTED, 13f, this)
        }
        val shown = findings.filter { it.weight > 0 || it.confirmed || it.code in setOf("link-service", "dest-change", "redirect-fail", "mb-fail") }
        if (shown.isNotEmpty()) {
            section("Γιατί")
            shown.forEach { f -> card { text("• " + f.message, if (f.confirmed) C.RED else if (f.weight >= 50) C.YELLOW else C.MUTED, 14f, this) } }
        }
    }

    fun input(hint: String, value: String?, secret: Boolean = false): EditText {
        val e = EditText(this).apply {
            setText(value ?: ""); this.hint = hint; setTextColor(C.TEXT); setHintTextColor(C.MUTED); textSize = 15f
            inputType = if (secret) InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD else InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
            setSingleLine(true)
        }
        root.addView(e, LinearLayout.LayoutParams(-1, -2))
        return e
    }

    fun go(cls: Class<*>) = startActivity(Intent(this, cls))
}

fun fmtTime(t: Long): String = SimpleDateFormat("dd/MM/yyyy HH:mm", Locale("el")).format(Date(t))
