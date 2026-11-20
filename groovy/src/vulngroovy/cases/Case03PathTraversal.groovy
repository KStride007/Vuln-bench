package vulngroovy.cases

import com.sun.net.httpserver.HttpExchange
import vulngroovy.Http

class Case03PathTraversal {

    static final File BASE_DIR = new File('docs')

    static String bad(HttpExchange ex) {
        String name = Http.param(ex, 'file')
        File target = new File(BASE_DIR, name)
        return target.text
    }

    static String good(HttpExchange ex) {
        String name = Http.param(ex, 'file')
        File root = BASE_DIR.canonicalFile
        File target = new File(BASE_DIR, name).canonicalFile
        if (!target.path.startsWith(root.path + File.separator)) {
            throw new SecurityException('path outside document root')
        }
        return target.text
    }

}
