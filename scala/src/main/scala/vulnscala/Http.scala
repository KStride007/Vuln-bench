package vulnscala

import com.sun.net.httpserver.HttpExchange
import java.net.URLDecoder

object Http {

  def param(ex: HttpExchange, name: String): String = {
    val query = ex.getRequestURI.getRawQuery
    if (query == null || query.isEmpty) {
      ""
    } else {
      val pairs = query.split("&").map { pair =>
        val i = pair.indexOf('=')
        val key = URLDecoder.decode(if (i < 0) pair else pair.substring(0, i), "UTF-8")
        val value = if (i < 0) "" else URLDecoder.decode(pair.substring(i + 1), "UTF-8")
        (key, value)
      }
      pairs.collectFirst { case (k, v) if k == name => v }.getOrElse("")
    }
  }

  def hex(bytes: Array[Byte]): String = bytes.map(b => "%02x".format(b & 0xff)).mkString

}
