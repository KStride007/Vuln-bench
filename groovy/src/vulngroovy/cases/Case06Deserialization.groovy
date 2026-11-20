package vulngroovy.cases

import com.sun.net.httpserver.HttpExchange
import groovy.json.JsonSlurper
import vulngroovy.Http

class Case06Deserialization {

    static String bad(HttpExchange ex) {
        String data = Http.param(ex, 'data')
        byte[] bytes = Base64.decoder.decode(data)
        def input = new ObjectInputStream(new ByteArrayInputStream(bytes))
        Object obj = input.readObject()
        return obj.toString()
    }

    static String good(HttpExchange ex) {
        String data = Http.param(ex, 'data')
        def parsed = new JsonSlurper().parseText(data)
        return parsed.toString()
    }

}
