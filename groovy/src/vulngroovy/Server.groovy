package vulngroovy

import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import vulngroovy.cases.*

class Server {

    static void main(String[] args) {
        int port = args ? args[0] as int : 8080

        new File('docs').mkdirs()
        new File('docs/readme.txt').text = 'public document'
        Db.seed()

        def cases = [
            case01: [Case01SqlInjection.&bad, Case01SqlInjection.&good],
            case02: [Case02CommandInjection.&bad, Case02CommandInjection.&good],
            case03: [Case03PathTraversal.&bad, Case03PathTraversal.&good],
            case04: [Case04Xss.&bad, Case04Xss.&good],
            case05: [Case05Xxe.&bad, Case05Xxe.&good],
            case06: [Case06Deserialization.&bad, Case06Deserialization.&good],
            case07: [Case07WeakHash.&bad, Case07WeakHash.&good],
            case08: [Case08HardcodedCredentials.&bad, Case08HardcodedCredentials.&good],
            case09: [Case09OpenRedirect.&bad, Case09OpenRedirect.&good],
            case10: [Case10InsecureRandom.&bad, Case10InsecureRandom.&good],
            case11: [Case11Ssrf.&bad, Case11Ssrf.&good],
            case12: [Case12CodeInjection.&bad, Case12CodeInjection.&good],
        ]

        HttpServer server = HttpServer.create(new InetSocketAddress('127.0.0.1', port), 0)
        cases.each { String id, List handlers ->
            server.createContext("/${id}/bad".toString()) { HttpExchange ex -> respond(ex, handlers[0]) }
            server.createContext("/${id}/good".toString()) { HttpExchange ex -> respond(ex, handlers[1]) }
        }
        server.createContext('/') { HttpExchange ex ->
            respond(ex) { 'VulnGroovy: intentionally vulnerable. Routes: /caseNN/bad and /caseNN/good' }
        }
        server.start()
        println "listening on ${port}"
    }

    static void respond(HttpExchange ex, Closure handler) {
        int status = 200
        String body
        try {
            body = handler(ex) ?: ''
            status = (ex.getAttribute('status') ?: 200) as int
        } catch (Throwable t) {
            status = 500
            body = "error: ${t.class.simpleName}: ${t.message}".toString()
        }
        byte[] bytes = body.getBytes('UTF-8')
        ex.responseHeaders.add('Content-Type', 'text/html; charset=utf-8')
        ex.sendResponseHeaders(status, status == 302 ? -1 : bytes.length)
        if (status != 302) {
            ex.responseBody.withStream { it.write(bytes) }
        }
        ex.close()
    }

}
