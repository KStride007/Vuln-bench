package vulnscala.cases

import com.sun.net.httpserver.HttpExchange
import vulnscala.{Db, Http}

object Case01SqlInjection {

  def bad(ex: HttpExchange): String = {
    val name = Http.param(ex, "name")
    val conn = Db.open()
    try {
      val rs = conn.createStatement().executeQuery("SELECT id, email FROM users WHERE name = '" + name + "'")
      val sb = new StringBuilder
      while (rs.next()) {
        sb.append(rs.getInt(1)).append(',').append(rs.getString(2)).append('\n')
      }
      sb.toString
    } finally {
      conn.close()
    }
  }

  def good(ex: HttpExchange): String = {
    val name = Http.param(ex, "name")
    val conn = Db.open()
    try {
      val ps = conn.prepareStatement("SELECT id, email FROM users WHERE name = ?")
      ps.setString(1, name)
      val rs = ps.executeQuery()
      val sb = new StringBuilder
      while (rs.next()) {
        sb.append(rs.getInt(1)).append(',').append(rs.getString(2)).append('\n')
      }
      sb.toString
    } finally {
      conn.close()
    }
  }

}
