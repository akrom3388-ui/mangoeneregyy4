package uz.mango.monitor

import android.app.Activity
import android.os.Bundle
import android.webkit.JavascriptInterface
import android.webkit.WebView
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

class MainActivity : Activity() {
    private lateinit var web: WebView
    private var token = ""
    private var tokenExp = 0L

    override fun onCreate(b: Bundle?) {
        super.onCreate(b)
        web = WebView(this)
        setContentView(web)
        web.settings.javaScriptEnabled = true
        web.settings.domStorageEnabled = true
        web.addJavascriptInterface(Bridge(), "Android")
        web.loadUrl("file:///android_asset/index.html")
    }

    override fun onBackPressed() { moveTaskToBack(true) }

    private fun sha(s: String) = MessageDigest.getInstance("SHA-256").digest(s.toByteArray())
        .joinToString("") { "%02x".format(it) }

    private fun hmac(msg: String, key: String): String {
        val m = Mac.getInstance("HmacSHA256")
        m.init(SecretKeySpec(key.toByteArray(), "HmacSHA256"))
        return m.doFinal(msg.toByteArray()).joinToString("") { "%02X".format(it) }
    }

    private fun raw(cfg: JSONObject, method: String, path: String, body: String, tok: String): String {
        val base = "https://openapi.tuya" + cfg.optString("region", "eu") + ".com"
        val t = System.currentTimeMillis().toString()
        val sts = "$method\n${sha(body)}\n\n$path"
        val sign = hmac(cfg.getString("id") + tok + t + sts, cfg.getString("secret"))
        val c = URL(base + path).openConnection() as HttpURLConnection
        c.requestMethod = method
        c.connectTimeout = 15000
        c.readTimeout = 20000
        c.setRequestProperty("client_id", cfg.getString("id"))
        c.setRequestProperty("sign", sign)
        c.setRequestProperty("t", t)
        c.setRequestProperty("sign_method", "HMAC-SHA256")
        if (tok.isNotEmpty()) c.setRequestProperty("access_token", tok)
        if (body.isNotEmpty()) {
            c.doOutput = true
            c.setRequestProperty("Content-Type", "application/json")
            c.outputStream.write(body.toByteArray())
        }
        val stream = if (c.responseCode < 400) c.inputStream else c.errorStream
        return stream.bufferedReader().readText()
    }

    private fun call(method: String, path: String, body: String): String {
        val cfg = JSONObject(getSharedPreferences("c", 0).getString("cfg", "{}")!!)
        if (!cfg.has("id") || !cfg.has("secret")) return """{"success":false,"msg":"Sozlamada Access ID/Secret kiriting"}"""
        if (token.isEmpty() || System.currentTimeMillis() > tokenExp) {
            val r = JSONObject(raw(cfg, "GET", "/v1.0/token?grant_type=1", "", ""))
            if (!r.optBoolean("success")) return r.toString()
            val res = r.getJSONObject("result")
            token = res.getString("access_token")
            tokenExp = System.currentTimeMillis() + (res.optLong("expire_time", 7200) - 120) * 1000
        }
        return raw(cfg, method, path, body, token)
    }

    inner class Bridge {
        @JavascriptInterface
        fun getCfg(): String = getSharedPreferences("c", 0).getString("cfg", "{}")!!

        @JavascriptInterface
        fun setCfg(s: String) {
            getSharedPreferences("c", 0).edit().putString("cfg", s).apply()
            token = ""
        }

        @JavascriptInterface
        fun api(id: Int, method: String, path: String, body: String) {
            Thread {
                val res = try { call(method, path, body) } catch (e: Exception) {
                    """{"success":false,"msg":${JSONObject.quote(e.toString())}}"""
                }
                runOnUiThread { web.evaluateJavascript("onApi($id,${JSONObject.quote(res)})", null) }
            }.start()
        }
    }
}
