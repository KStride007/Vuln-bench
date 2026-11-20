package vulnscala.cases

import com.sun.net.httpserver.HttpExchange
import java.net.URI
import scala.io.Source
import vulnscala.Http

object Case11Ssrf {

  def bad(ex: HttpExchange): String = {
    val url = Http.param(ex, "url")
    Source.fromURL(url).mkString
  }

  def good(ex: HttpExchange): String = {
    val url = Http.param(ex, "url")
    val uri = new URI(url)
    if (uri.getScheme != "https") {
      throw new IllegalArgumentException("https URL required")
    }
    if (!Seq("example.com", "api.example.com").contains(uri.getHost)) {
      throw new SecurityException("host not allowed")
    }
    Source.fromURL(uri.toURL).mkString
  }

}
