package vulngroovy.cases

import com.sun.net.httpserver.HttpExchange
import vulngroovy.Http

class Case02CommandInjection {

    static String bad(HttpExchange ex) {
        String host = Http.param(ex, 'host')
        def proc = ['/bin/sh', '-c', "echo lookup ${host}".toString()].execute()
        return proc.text
    }

    static String good(HttpExchange ex) {
        String host = Http.param(ex, 'host')
        if (!(host ==~ /^[A-Za-z0-9.-]{1,253}$/)) {
            throw new IllegalArgumentException('invalid host')
        }
        def proc = ['/bin/echo', 'lookup', host].execute()
        return proc.text
    }

}
