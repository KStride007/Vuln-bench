package vulnscala.cases

import com.sun.net.httpserver.HttpExchange
import java.io.{ByteArrayInputStream, ObjectInputStream}
import java.util.Base64
import vulnscala.Http

object Case06Deserialization {

  def bad(ex: HttpExchange): String = {
    val data = Http.param(ex, "data")
    val bytes = Base64.getDecoder.decode(data)
    val input = new ObjectInputStream(new ByteArrayInputStream(bytes))
    val obj = input.readObject()
    obj.toString
  }

  def good(ex: HttpExchange): String = {
    val data = Http.param(ex, "data")
    val pairs = data.split(",").map(_.split("=", 2)).filter(_.length == 2)
    pairs.map(p => p(0) + "=" + p(1)).mkString(",")
  }

}
