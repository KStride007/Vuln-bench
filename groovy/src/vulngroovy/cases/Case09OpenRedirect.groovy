package vulngroovy.cases

import com.sun.net.httpserver.HttpExchange
import vulngroovy.Http

class Case09OpenRedirect {

    static String bad(HttpExchange ex) {
        String target = Http.param(ex, 'next')
        ex.responseHeaders.add('Location', target)
        ex.setAttribute('status', 302)
        return ''
    }

    static String good(HttpExchange ex) {
        String target = Http.param(ex, 'next')
        boolean isLocal = target.startsWith('/') && !target.startsWith('//') && !target.startsWith('/\\')
        if (!isLocal) {
            target = '/'
        }
        ex.responseHeaders.add('Location', target)
        ex.setAttribute('status', 302)
        return ''
    }

}
