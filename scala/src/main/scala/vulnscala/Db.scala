package vulnscala

import java.sql.{Connection, DriverManager}

object Db {

  def open(): Connection = {
    Class.forName("org.h2.Driver")
    DriverManager.getConnection("jdbc:h2:mem:bench;DB_CLOSE_DELAY=-1", "sa", "")
  }

  def seed(): Unit = {
    val conn = open()
    try {
      val st = conn.createStatement()
      st.execute("CREATE TABLE IF NOT EXISTS users (id INT PRIMARY KEY, name VARCHAR(64), email VARCHAR(128))")
      st.execute("MERGE INTO users KEY(id) VALUES (1, 'alice', 'alice@example.test')")
      st.execute("MERGE INTO users KEY(id) VALUES (2, 'bob', 'bob@example.test')")
    } finally {
      conn.close()
    }
  }

}
