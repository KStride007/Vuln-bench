package vulnscala

import com.sun.net.httpserver.{HttpExchange, HttpHandler, HttpServer}
import java.io.File
import java.net.InetSocketAddress
import vulnscala.cases._

object Server {

  type Handler = HttpExchange => String

  def main(args: Array[String]): Unit = {
    val port = if (args.nonEmpty) args(0).toInt else 8080

    new File("docs").mkdirs()
    val readme = new java.io.PrintWriter(new File("docs/readme.txt"))
    try readme.print("public document") finally readme.close()
    Db.seed()

    val cases: Seq[(String, Handler, Handler)] = Seq(
      ("case01", Case01SqlInjection.bad _, Case01SqlInjection.good _),
      ("case02", Case02CommandInjection.bad _, Case02CommandInjection.good _),
      ("case03", Case03PathTraversal.bad _, Case03PathTraversal.good _),
      ("case04", Case04Xss.bad _, Case04Xss.good _),
      ("case05", Case05Xxe.bad _, Case05Xxe.good _),
      ("case06", Case06Deserialization.bad _, Case06Deserialization.good _),
      ("case07", Case07WeakHash.bad _, Case07WeakHash.good _),
      ("case08", Case08HardcodedCredentials.bad _, Case08HardcodedCredentials.good _),
      ("case09", Case09OpenRedirect.bad _, Case09OpenRedirect.good _),
      ("case10", Case10InsecureRandom.bad _, Case10InsecureRandom.good _),
      ("case11", Case11Ssrf.bad _, Case11Ssrf.good _),
      ("case12", Case12ReDoS.bad _, Case12ReDoS.good _)
    )

    val server = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0)
    for ((id, bad, good) <- cases) {
      server.createContext("/" + id + "/bad", handler(bad))
      server.createContext("/" + id + "/good", handler(good))
    }
    server.createContext("/", handler((_: HttpExchange) => "VulnScala: intentionally vulnerable. Routes: /caseNN/bad and /caseNN/good"))
    server.start()
    println("listening on " + port)
  }

  private def handler(f: Handler): HttpHandler = new HttpHandler {
    def handle(ex: HttpExchange): Unit = respond(ex, f)
  }

  private def respond(ex: HttpExchange, f: Handler): Unit = {
    var status = 200
    var body = ""
    try {
      body = f(ex)
      val attr = ex.getAttribute("status")
      if (attr != null) status = attr.asInstanceOf[Integer].intValue()
    } catch {
      case t: Throwable =>
        status = 500
        body = "error: " + t.getClass.getSimpleName + ": " + t.getMessage
    }
    val bytes = body.getBytes("UTF-8")
    ex.getResponseHeaders.add("Content-Type", "text/html; charset=utf-8")
    if (status == 302) {
      ex.sendResponseHeaders(status, -1)
    } else {
      ex.sendResponseHeaders(status, bytes.length.toLong)
      ex.getResponseBody.write(bytes)
    }
    ex.close()
  }

}
