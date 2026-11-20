package vulnscala.cases

import com.sun.net.httpserver.HttpExchange
import java.security.MessageDigest
import vulnscala.Http

object Case08HardcodedCredentials {

  def bad(ex: HttpExchange): String = {
    val supplied = Http.param(ex, "password")
    val adminPassword = "Winter2024!Prod"
    if (supplied == adminPassword) "welcome admin" else "denied"
  }

  def good(ex: HttpExchange): String = {
    val supplied = Http.param(ex, "password")
    val adminPassword = System.getenv("ADMIN_PASSWORD")
    if (adminPassword == null || adminPassword.isEmpty) {
      "denied"
    } else if (MessageDigest.isEqual(supplied.getBytes("UTF-8"), adminPassword.getBytes("UTF-8"))) {
      "welcome admin"
    } else {
      "denied"
    }
  }

}
