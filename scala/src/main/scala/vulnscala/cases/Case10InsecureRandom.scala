package vulnscala.cases

import com.sun.net.httpserver.HttpExchange
import java.security.SecureRandom
import vulnscala.Http

object Case10InsecureRandom {

  def bad(ex: HttpExchange): String = {
    val rnd = new scala.util.Random()
    val token = (1 to 16).map(_ => Integer.toHexString(rnd.nextInt(16))).mkString
    "reset-token=" + token
  }

  def good(ex: HttpExchange): String = {
    val bytes = new Array[Byte](16)
    new SecureRandom().nextBytes(bytes)
    "reset-token=" + Http.hex(bytes)
  }

}
