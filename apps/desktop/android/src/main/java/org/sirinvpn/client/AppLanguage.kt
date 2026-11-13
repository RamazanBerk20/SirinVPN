package org.sirinvpn.client

import android.app.LocaleManager
import android.content.Context
import android.content.res.Configuration
import android.os.Build
import android.os.LocaleList

/**
 * The app language chosen in SirinVPN or, on Android 13+, in Android's per-app language setting.
 * Android 13+ keeps it for the whole package (every process) and applies it to every context itself.
 * Android 12/12L has no per-app language: the :vpn controller stores the tag here, [wrap] applies it
 * to native contexts, and SirinPlugin mirrors it into AppCompat for the activity process.
 */
object AppLanguage {
    const val SYSTEM = "system"
    private const val FILE = "application-preferences"
    private const val KEY = "language"
    private val tag = Regex("^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8}){0,3}$")

    fun valid(value: String) = value == SYSTEM || value.length <= 35 && tag.matches(value)

    // Written by :vpn, also read by the Quick Settings tile in the main process: never trust a cached copy.
    @Suppress("DEPRECATION")
    private fun stored(context: Context) = context.getSharedPreferences(FILE, Context.MODE_MULTI_PROCESS).getString(KEY, SYSTEM) ?: SYSTEM

    /** "system" or the first language tag of the app's own locale list. */
    fun current(context: Context): String =
        if (Build.VERSION.SDK_INT >= 33) context.getSystemService(LocaleManager::class.java).applicationLocales.let { if (it.isEmpty()) SYSTEM else it[0].toLanguageTag() }
        else stored(context)

    /** Returns whether the language changed. Callable from any thread of either process. */
    fun set(context: Context, value: String): Boolean {
        require(valid(value))
        if (value == current(context)) return false
        if (Build.VERSION.SDK_INT >= 33) context.getSystemService(LocaleManager::class.java).applicationLocales =
            if (value == SYSTEM) LocaleList.getEmptyLocaleList() else LocaleList.forLanguageTags(value)
        else check(context.getSharedPreferences(FILE, 0).edit().putString(KEY, value).commit())
        return true
    }

    /** [base] with the chosen language on Android 12/12L; Android 13+ localizes [base] itself. */
    fun wrap(base: Context): Context {
        if (Build.VERSION.SDK_INT >= 33) return base
        val value = stored(base)
        if (value == SYSTEM) return base
        // setLocales also sets the layout direction (Arabic is right-to-left).
        return base.createConfigurationContext(Configuration(base.resources.configuration).apply { setLocales(LocaleList.forLanguageTags(value)) })
    }
}
