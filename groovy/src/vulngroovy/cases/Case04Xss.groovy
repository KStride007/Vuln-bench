package vulngroovy.cases

import com.sun.net.httpserver.HttpExchange
import groovy.xml.XmlUtil
import vulngroovy.Http

class Case04Xss {

    static String bad(HttpExchange ex) {
        String name = Http.param(ex, 'name')
        return "<html><body><h1>Hello ${name}</h1></body></html>".toString()
    }

    static String good(HttpExchange ex) {
        String name = Http.param(ex, 'name')
        return "<html><body><h1>Hello ${XmlUtil.escapeXml(name)}</h1></body></html>".toString()
    }

}
