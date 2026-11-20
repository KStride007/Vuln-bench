package vulngroovy.cases

import com.sun.net.httpserver.HttpExchange
import vulngroovy.Http

class Case12CodeInjection {

    static String bad(HttpExchange ex) {
        String expr = Http.param(ex, 'expr')
        return Eval.me(expr).toString()
    }

    static String good(HttpExchange ex) {
        String expr = Http.param(ex, 'expr')
        def m = expr =~ /^\s*(\d+)\s*([+*\/-])\s*(\d+)\s*$/
        if (!m.matches()) {
            throw new IllegalArgumentException('expected: <int> <op> <int>')
        }
        BigInteger a = new BigInteger(m.group(1))
        BigInteger b = new BigInteger(m.group(3))
        switch (m.group(2)) {
            case '+': return (a + b).toString()
            case '-': return (a - b).toString()
            case '*': return (a * b).toString()
            default:  return b == 0 ? 'undefined' : (a.divide(b)).toString()
        }
    }

}
