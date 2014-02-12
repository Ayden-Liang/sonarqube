/*
 * Copyright (C) 2009-2012 SonarSource SA
 * All rights reserved
 * mailto:contact AT sonarsource DOT com
 */
package com.sonar.runner.it;

import com.sonar.orchestrator.build.BuildResult;
import com.sonar.orchestrator.build.SonarRunner;
import com.sonar.orchestrator.locator.ResourceLocation;
import org.junit.Test;
import org.sonar.wsclient.services.Resource;
import org.sonar.wsclient.services.ResourceQuery;
import org.sonar.wsclient.services.Violation;
import org.sonar.wsclient.services.ViolationQuery;

import java.io.File;
import java.util.List;

import static org.fest.assertions.Assertions.assertThat;
import static org.junit.Assume.assumeTrue;

public class JavaTest extends RunnerTestCase {

  public JavaTest(boolean fork) {
    super(fork);
  }

  /**
   * SONARPLUGINS-2571
   */
  @Test
  public void display_version() {
    // The provided profile "Sonar way" can't be used because whitespaces are not supported by orchestrator on windows.
    orchestrator.getServer().restoreProfile(ResourceLocation.create("/sonar-way-profile.xml"));

    SonarRunner build = newRunner(new File("projects/java-sample")).setProfile("sonar-way");
    orchestrator.executeBuild(build);

    Resource project = orchestrator.getServer().getWsClient().find(new ResourceQuery("java:sample").setMetrics("files", "ncloc", "classes", "lcom4", "violations"));
    if (Util.runnerVersion(orchestrator).isGreaterThanOrEquals("2.1")) {
      // SONARPLUGINS-2399
      assertThat(project.getName()).isEqualTo("Java Sample, with comma");
    }
    assertThat(project.getDescription()).isEqualTo("This is a Java sample");
    assertThat(project.getVersion()).isEqualTo("1.2.3");
    if (!orchestrator.getServer().version().isGreaterThanOrEquals("4.2")) {
      assertThat(project.getLanguage()).isEqualTo("java");
    }
    assertThat(project.getMeasureIntValue("files")).isEqualTo(2);
    assertThat(project.getMeasureIntValue("classes")).isEqualTo(2);
    assertThat(project.getMeasureIntValue("ncloc")).isGreaterThan(10);
    assertThat(project.getMeasureIntValue("lcom4")).isNull(); // no bytecode
    assertThat(project.getMeasureIntValue("violations")).isGreaterThan(0);

    Resource file = orchestrator.getServer().getWsClient()
      .find(new ResourceQuery(helloFileKey()).setMetrics("files", "ncloc", "classes", "lcom4", "violations"));
    if (orchestrator.getServer().version().isGreaterThanOrEquals("4.2")) {
      assertThat(file.getName()).isEqualTo("Hello.java");
    } else {
      assertThat(file.getName()).isEqualTo("Hello");
    }
    assertThat(file.getMeasureIntValue("ncloc")).isEqualTo(7);
    assertThat(file.getMeasureIntValue("lcom4")).isNull(); // no bytecode
    assertThat(file.getMeasureIntValue("violations")).isGreaterThan(0);
  }

  /**
   * No bytecode, only sources
   */
  @Test
  public void scan_java_sources() {
    // The provided profile "Sonar way" can't be used because whitespaces are not supported by orchestrator on windows.
    orchestrator.getServer().restoreProfile(ResourceLocation.create("/sonar-way-profile.xml"));

    SonarRunner build = newRunner(new File("projects/java-sample"))
      .setProperty("sonarRunner.mode", "fork")
      .setProperty("sonar.verbose", "true")
      .addArguments("-e", "-X")
      .setProfile("sonar-way");
    // SONARPLUGINS-3061
    if (Util.runnerVersion(orchestrator).isGreaterThanOrEquals("2.3")) {
      // Add a trailing slash
      build.setProperty("sonar.host.url", orchestrator.getServer().getUrl() + "/");
    }
    orchestrator.executeBuild(build);

    Resource project = orchestrator.getServer().getWsClient().find(new ResourceQuery("java:sample").setMetrics("files", "ncloc", "classes", "lcom4", "violations"));
    if (Util.runnerVersion(orchestrator).isGreaterThanOrEquals("2.1")) {
      // SONARPLUGINS-2399
      assertThat(project.getName()).isEqualTo("Java Sample, with comma");
    }
    assertThat(project.getDescription()).isEqualTo("This is a Java sample");
    assertThat(project.getVersion()).isEqualTo("1.2.3");
    if (!orchestrator.getServer().version().isGreaterThanOrEquals("4.2")) {
      assertThat(project.getLanguage()).isEqualTo("java");
    }
    assertThat(project.getMeasureIntValue("files")).isEqualTo(2);
    assertThat(project.getMeasureIntValue("classes")).isEqualTo(2);
    assertThat(project.getMeasureIntValue("ncloc")).isGreaterThan(10);
    assertThat(project.getMeasureIntValue("lcom4")).isNull(); // no bytecode
    assertThat(project.getMeasureIntValue("violations")).isGreaterThan(0);

    Resource file = orchestrator.getServer().getWsClient()
      .find(new ResourceQuery(helloFileKey()).setMetrics("files", "ncloc", "classes", "lcom4", "violations"));
    if (orchestrator.getServer().version().isGreaterThanOrEquals("4.2")) {
      assertThat(file.getName()).isEqualTo("Hello.java");
    } else {
      assertThat(file.getName()).isEqualTo("Hello");
    }
    assertThat(file.getMeasureIntValue("ncloc")).isEqualTo(7);
    assertThat(file.getMeasureIntValue("lcom4")).isNull(); // no bytecode
    assertThat(file.getMeasureIntValue("violations")).isGreaterThan(0);
  }

  @Test
  public void scan_java_sources_and_bytecode() {
    orchestrator.getServer().restoreProfile(ResourceLocation.create("/requires-bytecode-profile.xml"));
    SonarRunner build = newRunner(new File("projects/java-bytecode")).setProfile("requires-bytecode");
    orchestrator.executeBuild(build);

    Resource project = orchestrator.getServer().getWsClient().find(new ResourceQuery("java:bytecode").setMetrics("lcom4", "violations"));
    assertThat(project.getName()).isEqualTo("Java Bytecode Sample");
    if (!orchestrator.getServer().version().isGreaterThanOrEquals("4.1")) {
      // SONAR-4853 LCOM4 is no more computed on SQ 4.1
      assertThat(project.getMeasureIntValue("lcom4")).isGreaterThanOrEqualTo(1);
    }
    assertThat(project.getMeasureIntValue("violations")).isGreaterThan(0);

    Resource file = orchestrator.getServer().getWsClient().find(new ResourceQuery(findbugsFileKey()).setMetrics("lcom4", "violations"));
    assertThat(file.getMeasureIntValue("lcom4")).isGreaterThanOrEqualTo(1);
    assertThat(file.getMeasureIntValue("violations")).isGreaterThan(0);

    // findbugs is executed on bytecode
    ViolationQuery query = ViolationQuery.createForResource("java:bytecode").setDepth(-1).setRuleKeys("findbugs:DM_EXIT");
    List<Violation> violations = orchestrator.getServer().getWsClient().findAll(query);
    assertThat(violations).hasSize(1);
    assertThat(violations.get(0).getRuleKey()).isEqualTo("findbugs:DM_EXIT");

    // Squid performs analysis of dependencies
    query = ViolationQuery.createForResource("java:bytecode").setDepth(-1).setRuleKeys("squid:CallToDeprecatedMethod");
    violations = orchestrator.getServer().getWsClient().findAll(query);
    assertThat(violations).hasSize(1);
    assertThat(violations.get(0).getRuleKey()).isEqualTo("squid:CallToDeprecatedMethod");
  }

  @Test
  public void basedir_contains_java_sources() {
    assumeTrue(orchestrator.getServer().version().isGreaterThanOrEquals("3.0"));

    // The provided profile "Sonar way" can't be used because whitespaces are not supported by orchestrator on windows.
    orchestrator.getServer().restoreProfile(ResourceLocation.create("/sonar-way-profile.xml"));
    SonarRunner build = newRunner(new File("projects/basedir-with-source")).setProfile("sonar-way");
    orchestrator.executeBuild(build);

    Resource project = orchestrator.getServer().getWsClient().find(new ResourceQuery("java:basedir-with-source").setMetrics("files", "ncloc"));
    assertThat(project.getMeasureIntValue("files")).isEqualTo(1);
    assertThat(project.getMeasureIntValue("ncloc")).isGreaterThan(1);
  }

  /**
   * Replace the maven format groupId:artifactId by a single key
   */
  @Test
  public void should_support_simple_project_keys() {
    assumeTrue(orchestrator.getServer().version().isGreaterThanOrEquals("3.0"));

    // The provided profile "Sonar way" can't be used because whitespaces are not supported by orchestrator on windows.
    orchestrator.getServer().restoreProfile(ResourceLocation.create("/sonar-way-profile.xml"));
    SonarRunner build = newRunner(new File("projects/java-sample"))
      .setProjectKey("SAMPLE")
      .setProfile("sonar-way");
    orchestrator.executeBuild(build);

    Resource project = orchestrator.getServer().getWsClient().find(new ResourceQuery("SAMPLE").setMetrics("files", "ncloc"));
    assertThat(project.getMeasureIntValue("files")).isEqualTo(2);
    assertThat(project.getMeasureIntValue("ncloc")).isGreaterThan(1);
  }

  /**
   * SONARPLUGINS-1230
   */
  @Test
  public void should_override_working_dir_with_relative_path() {
    SonarRunner build = newRunner(new File("projects/override-working-dir"))
      .setProperty("sonar.working.directory", ".overridden-relative-sonar");
    orchestrator.executeBuild(build);

    assertThat(new File("projects/override-working-dir/.sonar")).doesNotExist();
    assertThat(new File("projects/override-working-dir/.overridden-relative-sonar")).exists().isDirectory();
  }

  /**
   * SONARPLUGINS-1230
   */
  @Test
  public void should_override_working_dir_with_absolute_path() {
    File projectHome = new File("projects/override-working-dir");
    SonarRunner build = newRunner(projectHome)
      .setProperty("sonar.working.directory", new File(projectHome, ".overridden-absolute-sonar").getAbsolutePath());
    orchestrator.executeBuild(build);

    assertThat(new File("projects/override-working-dir/.sonar")).doesNotExist();
    assertThat(new File("projects/override-working-dir/.overridden-absolute-sonar")).exists().isDirectory();
  }

  /**
   * SONARPLUGINS-1856
   */
  @Test
  public void should_fail_if_source_dir_does_not_exist() {
    SonarRunner build = newRunner(new File("projects/bad-source-dirs"));

    BuildResult result = orchestrator.executeBuildQuietly(build);
    assertThat(result.getStatus()).isNotEqualTo(0);
    // with the following message
    assertThat(result.getLogs()).contains("The folder 'bad' does not exist for 'bad-source-dirs'");
  }

  /**
   * SONARPLUGINS-2203
   */
  @Test
  public void should_log_message_when_deprecated_properties_are_used() {
    SonarRunner build = newRunner(new File("projects/using-deprecated-props"));

    BuildResult result = orchestrator.executeBuild(build);
    String logs = result.getLogs();
    assertThat(logs).contains("/!\\ The 'sources' property is deprecated and is replaced by 'sonar.sources'. Don't forget to update your files.");
    assertThat(logs).contains("/!\\ The 'tests' property is deprecated and is replaced by 'sonar.tests'. Don't forget to update your files.");
    assertThat(logs).contains("/!\\ The 'binaries' property is deprecated and is replaced by 'sonar.binaries'. Don't forget to update your files.");
    assertThat(logs).contains("/!\\ The 'libraries' property is deprecated and is replaced by 'sonar.libraries'. Don't forget to update your files.");
  }

  /**
   * SONARPLUGINS-2256
   */
  @Test
  public void should_warn_when_analysis_is_platform_dependent() {
    SonarRunner build = newRunner(new File("projects/java-sample"));
    String log = orchestrator.executeBuild(build).getLogs();

    // Note: we can't really check the locale value and the charset because the ones used during the Sonar analysis may not be the ones
    // used to launch the tests. But we can check that the analysis is platform dependent (i.e. "sonar.sourceEncoding" hasn't been set).
    assertThat(log).contains("Default locale:");
    assertThat(log).contains(", source code encoding:");
    assertThat(log).contains("(analysis is platform dependent)");
  }

  @Test
  public void should_fail_if_unable_to_connect() {
    assumeTrue(Util.runnerVersion(orchestrator).isGreaterThan("2.1"));

    SonarRunner build = newRunner(new File("projects/multi-module/failures/unexisting-config-file"))
      .setProperty("sonar.host.url", "http://foo");

    BuildResult result = orchestrator.executeBuildQuietly(build);
    // expect build failure
    assertThat(result.getStatus()).isNotEqualTo(0);
    // with the following message
    assertThat(result.getLogs()).contains("ERROR: Sonar server 'http://foo' can not be reached");
  }

  private String findbugsFileKey() {
    if (orchestrator.getServer().version().isGreaterThanOrEquals("4.2")) {
      return "java:bytecode:src/HasFindbugsViolation.java";
    } else {
      return "java:bytecode:[default].HasFindbugsViolation";
    }
  }

  private String helloFileKey() {
    if (orchestrator.getServer().version().isGreaterThanOrEquals("4.2")) {
      return "java:sample:src/basic/Hello.java";
    } else {
      return "java:sample:basic.Hello";
    }
  }
}
