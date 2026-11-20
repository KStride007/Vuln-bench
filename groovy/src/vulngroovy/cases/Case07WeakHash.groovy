package vulngroovy.cases

import com.sun.net.httpserver.HttpExchange
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import vulngroovy.Http

class Case07WeakHash {

    static String bad(HttpExchange ex) {
        String password = Http.param(ex, 'password')
        byte[] digest = MessageDigest.getInstance('MD5').digest(password.getBytes('UTF-8'))
        return digest.encodeHex().toString()
    }

    static String good(HttpExchange ex) {
        String password = Http.param(ex, 'password')
        byte[] salt = new byte[16]
        new SecureRandom().nextBytes(salt)
        def spec = new PBEKeySpec(password.toCharArray(), salt, 210000, 256)
        byte[] digest = SecretKeyFactory.getInstance('PBKDF2WithHmacSHA256').generateSecret(spec).encoded
        return salt.encodeHex().toString() + ':' + digest.encodeHex().toString()
    }

}
