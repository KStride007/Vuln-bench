package vulngroovy.cases

import com.sun.net.httpserver.HttpExchange
import groovy.sql.Sql
import vulngroovy.Db
import vulngroovy.Http

class Case01SqlInjection {

    static String bad(HttpExchange ex) {
        String name = Http.param(ex, 'name')
        Sql sql = Db.open()
        try {
            def rows = sql.rows("SELECT id, email FROM users WHERE name = '" + name + "'")
            return rows.collect { "${it.id},${it.email}" }.join('\n')
        } finally {
            sql.close()
        }
    }

    static String good(HttpExchange ex) {
        String name = Http.param(ex, 'name')
        Sql sql = Db.open()
        try {
            def rows = sql.rows('SELECT id, email FROM users WHERE name = ?', [name])
            return rows.collect { "${it.id},${it.email}" }.join('\n')
        } finally {
            sql.close()
        }
    }

}
