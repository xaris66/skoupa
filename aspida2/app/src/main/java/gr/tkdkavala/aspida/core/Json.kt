package gr.tkdkavala.aspida.core

/** Μικρός, αυστηρός αναλυτής JSON (χωρίς εξαρτήσεις) για τις απαντήσεις των υπηρεσιών. */
object Json {
    fun parse(text: String): Any? {
        val p = Parser(text)
        p.ws()
        val v = p.value(0)
        p.ws()
        require(p.i == text.length) { "Περιττοί χαρακτήρες στο JSON" }
        return v
    }

    private class Parser(val s: String) {
        var i = 0
        fun ws() { while (i < s.length && s[i].isWhitespace()) i++ }
        fun value(depth: Int): Any? {
            require(depth < 64) { "Πολύ βαθύ JSON" }
            ws()
            require(i < s.length) { "Τέλος JSON" }
            return when (s[i]) {
                '{' -> obj(depth)
                '[' -> arr(depth)
                '"' -> str()
                't' -> lit("true", true)
                'f' -> lit("false", false)
                'n' -> lit("null", null)
                else -> num()
            }
        }
        fun lit(w: String, v: Any?): Any? {
            require(s.startsWith(w, i)) { "Άκυρο JSON" }
            i += w.length; return v
        }
        fun num(): Any {
            val st = i
            while (i < s.length && (s[i].isDigit() || s[i] in "+-.eE")) i++
            val t = s.substring(st, i)
            require(t.isNotEmpty()) { "Άκυρος αριθμός" }
            return t.toLongOrNull() ?: t.toDouble()
        }
        fun str(): String {
            i++
            val sb = StringBuilder()
            while (true) {
                require(i < s.length) { "Ανοιχτό string" }
                val c = s[i++]
                when (c) {
                    '"' -> return sb.toString()
                    '\\' -> {
                        val e = s[i++]
                        when (e) {
                            'n' -> sb.append('\n'); 't' -> sb.append('\t'); 'r' -> sb.append('\r')
                            'b' -> sb.append('\b'); 'f' -> sb.append('\u000c')
                            'u' -> { sb.append(s.substring(i, i + 4).toInt(16).toChar()); i += 4 }
                            else -> sb.append(e)
                        }
                    }
                    else -> sb.append(c)
                }
            }
        }
        fun arr(depth: Int): List<Any?> {
            i++; val out = ArrayList<Any?>(); ws()
            if (s[i] == ']') { i++; return out }
            while (true) {
                out.add(value(depth + 1)); ws()
                when (s[i++]) { ',' -> continue; ']' -> return out; else -> error("Άκυρος πίνακας") }
            }
        }
        fun obj(depth: Int): Map<String, Any?> {
            i++; val out = LinkedHashMap<String, Any?>(); ws()
            if (s[i] == '}') { i++; return out }
            while (true) {
                ws(); val k = str(); ws()
                require(s[i++] == ':') { "Λείπει ':'" }
                out[k] = value(depth + 1); ws()
                when (s[i++]) { ',' -> continue; '}' -> return out; else -> error("Άκυρο αντικείμενο") }
            }
        }
    }
}
