import sbt._
import com.twitter.sbt._

class JoauthProject(info: ProjectInfo)
  extends StandardProject(info)
  with DefaultRepos
  with ProjectDependencies
  with SubversionPublisher
  with PublishSite
{
  override def managedStyle = ManagedStyle.Maven
  override def disableCrossPaths = true

  projectDependencies(
    "util" ~ "util-core",
    "util" ~ "util-codec"
  )

  val specs   = "org.scala-tools.testing" % "specs_2.8.1" % "1.6.8" % "test" withSources()
  val junit   = "junit"                   % "junit"       % "4.8.1" % "test" withSources()
  val mockito = "org.mockito"             % "mockito-all" % "1.8.5" % "test" withSources()

  override def subversionRepository = Some("https://svn.twitter.biz/maven-public")
}
