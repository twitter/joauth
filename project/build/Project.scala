import sbt._
import com.twitter.sbt._

class JoauthProject(info: ProjectInfo) extends StandardProject(info) with SubversionPublisher {
  val servletapi = "javax.servlet" % "servlet-api" % "2.5"
  val codec = "commons-codec" % "commons-codec" % "1.4"
  val thrust = "com.twitter" % "thrust-core" % "1.0.1"
  val specs = "org.scala-tools.testing" %% "specs" % "1.6.6" % "test"
  val mockitoall = "org.mockito" % "mockito-all" % "1.8.4" % "test"

  override def subversionRepository = Some("http://svn.local.twitter.com/maven-public")
}
