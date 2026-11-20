package vulnscala.cases

import com.sun.net.httpserver.HttpExchange
import java.security.{MessageDigest, SecureRandom}
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import vulnscala.Http

object Case07WeakHash {

  def bad(ex: HttpExchange): String = {
    val password = Http.param(ex, "password")
    val digest = MessageDigest.getInstance("MD5").digest(password.getBytes("UTF-8"))
    Http.hex(digest)
  }

  def good(ex: HttpExchange): String = {
    val password = Http.param(ex, "password")
    val salt = new Array[Byte](16)
    new SecureRandom().nextBytes(salt)
    val spec = new PBEKeySpec(password.toCharArray, salt, 210000, 256)
    val digest = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded
    Http.hex(salt) + ":" + Http.hex(digest)
  }

}
