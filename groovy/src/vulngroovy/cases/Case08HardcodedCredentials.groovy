package vulngroovy.cases

import com.sun.net.httpserver.HttpExchange
import java.security.MessageDigest
import vulngroovy.Http

class Case08HardcodedCredentials {

    static String bad(HttpExchange ex) {
        String supplied = Http.param(ex, 'password')
        String adminPassword = 'Winter2024!Prod'
        if (supplied == adminPassword) {
            return 'welcome admin'
        }
        return 'denied'
    }

    static String good(HttpExchange ex) {
        String supplied = Http.param(ex, 'password')
        String adminPassword = System.getenv('ADMIN_PASSWORD')
        if (!adminPassword) {
            return 'denied'
        }
        if (MessageDigest.isEqual(supplied.getBytes('UTF-8'), adminPassword.getBytes('UTF-8'))) {
            return 'welcome admin'
        }
        return 'denied'
    }

}
