package vulngroovy.cases

import com.sun.net.httpserver.HttpExchange
import java.security.SecureRandom

class Case10InsecureRandom {

    static String bad(HttpExchange ex) {
        Random rnd = new Random()
        String token = (1..16).collect { Integer.toHexString(rnd.nextInt(16)) }.join('')
        return "reset-token=${token}".toString()
    }

    static String good(HttpExchange ex) {
        byte[] bytes = new byte[16]
        new SecureRandom().nextBytes(bytes)
        return "reset-token=${bytes.encodeHex()}".toString()
    }

}
