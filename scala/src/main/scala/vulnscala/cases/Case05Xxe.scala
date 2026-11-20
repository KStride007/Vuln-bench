package vulnscala.cases

import com.sun.net.httpserver.HttpExchange
import java.io.StringReader
import javax.xml.parsers.DocumentBuilderFactory
import org.xml.sax.InputSource
import vulnscala.Http

object Case05Xxe {

  def bad(ex: HttpExchange): String = {
    val xml = Http.param(ex, "xml")
    val factory = DocumentBuilderFactory.newInstance()
    val doc = factory.newDocumentBuilder().parse(new InputSource(new StringReader(xml)))
    doc.getDocumentElement.getTextContent
  }

  def good(ex: HttpExchange): String = {
    val xml = Http.param(ex, "xml")
    val factory = DocumentBuilderFactory.newInstance()
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
    factory.setFeature("http://xml.org/sax/features/external-general-entities", false)
    factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false)
    factory.setXIncludeAware(false)
    factory.setExpandEntityReferences(false)
    val doc = factory.newDocumentBuilder().parse(new InputSource(new StringReader(xml)))
    doc.getDocumentElement.getTextContent
  }

}
