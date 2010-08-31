import sbt._
import com.twitter.sbt._


class JoauthProject(info: ProjectInfo) extends StandardProject(info) {
  val vscaladoc = "org.scala-tools" % "vscaladoc" % "1.1-md-3"
  val servletapi = "javax.servlet" % "servlet-api" % "2.5"
  val specs = "org.scala-tools.testing" % "specs" % "1.6.2.1" % "test"
  val mockitoall = "org.mockito" % "mockito-all" % "1.8.1" % "test"
}
