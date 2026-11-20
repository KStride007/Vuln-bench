package vulngroovy.extras

// Dependency declared only through @Grab in source. Manifest-based SCA scanners
// (build.gradle, pom.xml, lockfiles) cannot see it; source-aware scanners can.
// This file is excluded from the build and is never loaded by the running server.
@Grab('org.apache.commons:commons-text:1.9')
import org.apache.commons.text.StringSubstitutor

class Report {

    static String render(String template, Map<String, String> values) {
        return new StringSubstitutor(values).replace(template)
    }

}
