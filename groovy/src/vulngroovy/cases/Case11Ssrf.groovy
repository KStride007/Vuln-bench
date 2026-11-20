package vulngroovy.cases

import com.sun.net.httpserver.HttpExchange
import vulngroovy.Http

class Case11Ssrf {

    static String bad(HttpExchange ex) {
        String url = Http.param(ex, 'url')
        return new URL(url).text
    }

    static String good(HttpExchange ex) {
        String url = Http.param(ex, 'url')
        URI uri = new URI(url)
        if (uri.scheme != 'https') {
            throw new IllegalArgumentException('https URL required')
        }
        if (!(uri.host in ['example.com', 'api.example.com'])) {
            throw new SecurityException('host not allowed')
        }
        return uri.toURL().text
    }

}
