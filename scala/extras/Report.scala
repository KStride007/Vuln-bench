//> using dep "org.apache.commons:commons-text:1.9"
// Source-only dependency declaration (Scala-CLI directive). Not part of the sbt build and not compiled
// by build.sbt: this is the SCA blind-spot probe (CVE-2022-42889, commons-text 1.9).
package vulnscala.extras

import org.apache.commons.text.StringSubstitutor

object Report {
  def render(template: String): String = StringSubstitutor.createInterpolator().replace(template)
}
