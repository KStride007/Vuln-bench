package vulnscala.cases

import com.sun.net.httpserver.HttpExchange
import scala.sys.process._
import vulnscala.Http

object Case02CommandInjection {

  def bad(ex: HttpExchange): String = {
    val host = Http.param(ex, "host")
    Seq("/bin/sh", "-c", "echo lookup " + host).!!
  }

  def good(ex: HttpExchange): String = {
    val host = Http.param(ex, "host")
    if (!host.matches("^[A-Za-z0-9.-]{1,253}$")) {
      throw new IllegalArgumentException("invalid host")
    }
    Seq("/bin/echo", "lookup", host).!!
  }

}
