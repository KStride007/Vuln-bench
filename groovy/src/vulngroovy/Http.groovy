package vulngroovy

import com.sun.net.httpserver.HttpExchange

class Http {

    static String param(HttpExchange ex, String name) {
        String query = ex.requestURI.rawQuery
        if (!query) {
            return ''
        }
        for (String pair : query.split('&')) {
            int i = pair.indexOf('=')
            String key = URLDecoder.decode(i < 0 ? pair : pair.substring(0, i), 'UTF-8')
            if (key == name) {
                return i < 0 ? '' : URLDecoder.decode(pair.substring(i + 1), 'UTF-8')
            }
        }
        return ''
    }

}
