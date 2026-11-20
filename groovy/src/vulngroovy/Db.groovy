package vulngroovy

import groovy.sql.Sql

class Db {

    static Sql open() {
        Sql sql = Sql.newInstance('jdbc:h2:mem:bench;DB_CLOSE_DELAY=-1', 'sa', '', 'org.h2.Driver')
        return sql
    }

    static void seed() {
        Sql sql = open()
        sql.execute('CREATE TABLE IF NOT EXISTS users (id INT PRIMARY KEY, name VARCHAR(64), email VARCHAR(128))')
        sql.execute("MERGE INTO users KEY(id) VALUES (1, 'alice', 'alice@example.test')")
        sql.execute("MERGE INTO users KEY(id) VALUES (2, 'bob', 'bob@example.test')")
        sql.close()
    }

}
