package gr.tkdkavala.aspida.core

/**
 * Γνωστές υπηρεσίες που μιμούνται συχνά οι απατεώνες, με τα ΕΠΙΣΗΜΑ καταχωρίσιμα domains τους.
 * Η λίστα χρησιμοποιείται ΜΟΝΟ για προειδοποίηση μίμησης — ποτέ για αποκλεισμό
 * και ποτέ για να χαρακτηριστεί κάτι «ασφαλές».
 */
object Brands {
    data class Brand(val name: String, val tokens: List<String>, val officialDomains: Set<String>)

    val all = listOf(
        Brand("Facebook", listOf("facebook", "faceb00k"), setOf("facebook.com", "fb.com", "fb.me", "fb.watch", "facebook.net", "fbcdn.net", "messenger.com", "meta.com", "m.me", "fbsbx.com")),
        Brand("Instagram", listOf("instagram"), setOf("instagram.com", "cdninstagram.com", "ig.me", "instagr.am", "facebook.com", "meta.com")),
        Brand("Messenger", listOf("messenger"), setOf("messenger.com", "m.me", "facebook.com", "meta.com")),
        Brand("WhatsApp", listOf("whatsapp"), setOf("whatsapp.com", "whatsapp.net", "wa.me", "meta.com")),
        Brand("Google", listOf("google", "gmail"), setOf("google.com", "google.gr", "gmail.com", "goo.gl", "g.co", "googleusercontent.com", "gstatic.com", "withgoogle.com", "youtube.com", "googleapis.com", "android.com", "blog.google", "google")),
        Brand("YouTube", listOf("youtube"), setOf("youtube.com", "youtu.be", "google.com", "ytimg.com")),
        Brand("Apple", listOf("icloud", "appleid"), setOf("apple.com", "icloud.com")),
        Brand("Microsoft", listOf("microsoft", "outlook", "office365", "hotmail"), setOf("microsoft.com", "live.com", "outlook.com", "office.com", "microsoftonline.com", "hotmail.com", "office365.com", "sharepoint.com")),
        Brand("PayPal", listOf("paypal"), setOf("paypal.com", "paypal.me", "paypalobjects.com")),
        Brand("Netflix", listOf("netflix"), setOf("netflix.com", "nflxext.com")),
        Brand("Amazon", listOf("amazon"), setOf("amazon.com", "amazon.de", "amazon.co.uk", "amazon.it", "amazon.fr", "amazon.es", "amzn.to", "amazonaws.com")),
        Brand("Cosmote / Telekom", listOf("cosmote", "telekom"), setOf("cosmote.gr", "telekom.gr", "telekom.de", "telekom.com", "cosmote.com")),
        Brand("Τράπεζα Πειραιώς", listOf("piraeusbank", "winbank"), setOf("piraeusbank.gr", "winbank.gr")),
        Brand("Eurobank", listOf("eurobank"), setOf("eurobank.gr")),
        Brand("Alpha Bank", listOf("alphabank"), setOf("alpha.gr", "alphabank.gr")),
        Brand("Εθνική Τράπεζα", listOf("ethniki", "nbgbank"), setOf("nbg.gr")),
        Brand("ΕΛΤΑ", listOf("elta"), setOf("elta.gr", "elta-courier.gr")),
        Brand("ACS", listOf("acscourier"), setOf("acscourier.net", "acscourier.gr")),
        Brand("ΑΑΔΕ / gov.gr", listOf("taxisnet", "gsis", "aade", "govgr"), setOf("gov.gr", "gsis.gr", "aade.gr")),
        Brand("DHL", listOf("dhl"), setOf("dhl.com", "dhl.de", "dhl.gr")),
        Brand("Viber", listOf("viber"), setOf("viber.com")),
    ).filter { it.tokens.isNotEmpty() }

    /**
     * Υπηρεσίες «έξυπνων συνδέσμων» και συντόμευσης που χρησιμοποιούν νόμιμα οι εταιρείες
     * (π.χ. cosmote.go.link). Εδώ δεν κρίνουμε το όνομα — ακολουθούμε την ανακατεύθυνση
     * και ελέγχουμε τον ΤΕΛΙΚΟ προορισμό.
     */
    val linkServices = setOf(
        "go.link", "app.link", "page.link", "onelink.me", "adj.st", "bit.ly", "tinyurl.com", "t.co",
        "goo.gl", "is.gd", "cutt.ly", "rb.gy", "ow.ly", "buff.ly", "lnkd.in", "t.ly", "shorturl.at",
        "s.id", "linktr.ee", "l.facebook.com", "l.instagram.com", "lm.facebook.com",
    )

    /** Επίσημο αν ταιριάζει ακριβώς ή είναι υποτομέας (π.χ. www.gov.gr: το gov.gr είναι δημόσια κατάληξη). */
    fun isOfficial(brand: Brand, registrable: String?): Boolean =
        registrable != null && brand.officialDomains.any { registrable == it || registrable.endsWith(".$it") }
}
