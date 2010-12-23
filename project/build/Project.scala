import sbt._
import com.twitter.sbt._

class JoauthProject(info: ProjectInfo)
  extends StandardProject(info)
  with SubversionPublisher
  with InlineDependencies
{
  override def managedStyle = ManagedStyle.Maven
  override def disableCrossPaths = true

  inline("com.twitter" % "thrust" % "1.3.6")

  val servletapi = "javax.servlet" % "servlet-api" % "2.5"
  val codec = "commons-codec" % "commons-codec" % "1.4"
  val specs = "org.scala-tools.testing" %% "specs" % "1.6.6" % "test"
  val mockitoall = "org.mockito" % "mockito-all" % "1.8.4" % "test"

  override def subversionRepository = Some("http://svn.local.twitter.com/maven-public")
}
