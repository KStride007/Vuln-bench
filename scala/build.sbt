name := "vuln-scala"
version := "0.1.0"
scalaVersion := "2.13.8"

// Intentionally vulnerable dependency versions (SCA ground truth, see manifest.json)
libraryDependencies ++= Seq(
  "com.typesafe.play"            %% "play"             % "2.8.15",
  "com.fasterxml.jackson.core"    % "jackson-databind" % "2.9.8",
  "org.yaml"                      % "snakeyaml"        % "1.26",
  "org.apache.logging.log4j"      % "log4j-core"       % "2.14.1",
  "com.h2database"                % "h2"               % "2.1.214"
)
