package vulngroovy.cases

import com.sun.net.httpserver.HttpExchange
import javax.xml.parsers.DocumentBuilderFactory
import org.xml.sax.InputSource
import vulngroovy.Http

class Case05Xxe {

    static String bad(HttpExchange ex) {
        String xml = Http.param(ex, 'xml')
        def factory = DocumentBuilderFactory.newInstance()
        def doc = factory.newDocumentBuilder().parse(new InputSource(new StringReader(xml)))
        return doc.documentElement.textContent
    }

    static String good(HttpExchange ex) {
        String xml = Http.param(ex, 'xml')
        def factory = DocumentBuilderFactory.newInstance()
        factory.setFeature('http://apache.org/xml/features/disallow-doctype-decl', true)
        factory.setFeature('http://xml.org/sax/features/external-general-entities', false)
        factory.setFeature('http://xml.org/sax/features/external-parameter-entities', false)
        factory.setXIncludeAware(false)
        factory.setExpandEntityReferences(false)
        def doc = factory.newDocumentBuilder().parse(new InputSource(new StringReader(xml)))
        return doc.documentElement.textContent
    }

}
