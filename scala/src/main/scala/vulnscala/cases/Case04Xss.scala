package vulnscala.cases

import com.sun.net.httpserver.HttpExchange
import vulnscala.Http

object Case04Xss {

  def bad(ex: HttpExchange): String = {
    val name = Http.param(ex, "name")
    "<html><body><h1>Hello " + name + "</h1></body></html>"
  }

  def good(ex: HttpExchange): String = {
    val name = Http.param(ex, "name")
    val escaped = name.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&#39;")
    "<html><body><h1>Hello " + escaped + "</h1></body></html>"
  }

}
