package vulnscala.cases

import com.sun.net.httpserver.HttpExchange
import vulnscala.Http

object Case09OpenRedirect {

  def bad(ex: HttpExchange): String = {
    val target = Http.param(ex, "next")
    ex.getResponseHeaders.add("Location", target)
    ex.setAttribute("status", Integer.valueOf(302))
    ""
  }

  def good(ex: HttpExchange): String = {
    val target = Http.param(ex, "next")
    val isLocal = target.startsWith("/") && !target.startsWith("//") && !target.startsWith("/\\")
    val safe = if (isLocal) target else "/"
    ex.getResponseHeaders.add("Location", safe)
    ex.setAttribute("status", Integer.valueOf(302))
    ""
  }

}
