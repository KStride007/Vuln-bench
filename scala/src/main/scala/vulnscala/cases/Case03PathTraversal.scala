package vulnscala.cases

import com.sun.net.httpserver.HttpExchange
import java.io.File
import scala.io.Source
import vulnscala.Http

object Case03PathTraversal {

  val BaseDir = new File("docs")

  def bad(ex: HttpExchange): String = {
    val name = Http.param(ex, "file")
    val target = new File(BaseDir, name)
    Source.fromFile(target).mkString
  }

  def good(ex: HttpExchange): String = {
    val name = Http.param(ex, "file")
    val root = BaseDir.getCanonicalFile
    val target = new File(BaseDir, name).getCanonicalFile
    if (!target.getPath.startsWith(root.getPath + File.separator)) {
      throw new SecurityException("path outside document root")
    }
    Source.fromFile(target).mkString
  }

}
