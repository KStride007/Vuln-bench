package vulnscala.cases

import com.sun.net.httpserver.HttpExchange
import java.util.regex.Pattern
import vulnscala.Http

object Case12ReDoS {

  def bad(ex: HttpExchange): String = {
    val value = Http.param(ex, "value")
    Pattern.compile("^(a+)+\\1$").matcher(value).matches().toString
  }

  def good(ex: HttpExchange): String = {
    val value = Http.param(ex, "value")
    if (value.length > 64) {
      throw new IllegalArgumentException("value too long")
    }
    Pattern.compile("^a+$").matcher(value).matches().toString
  }

}
