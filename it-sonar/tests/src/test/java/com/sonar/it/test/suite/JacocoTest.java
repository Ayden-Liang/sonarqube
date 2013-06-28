/*
 * Copyright (C) 2009-2012 SonarSource SA
 * All rights reserved
 * mailto:contact AT sonarsource DOT com
 */

package com.sonar.it.test.suite;

import com.sonar.it.ItUtils;
import com.sonar.orchestrator.Orchestrator;
import com.sonar.orchestrator.build.MavenBuild;
import com.sonar.orchestrator.selenium.Selenese;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;
import org.sonar.wsclient.services.Resource;
import org.sonar.wsclient.services.ResourceQuery;

import static org.hamcrest.Matchers.closeTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.number.OrderingComparisons.greaterThan;
import static org.junit.Assert.assertThat;

public class JacocoTest {

  @ClassRule
  public static Orchestrator orchestrator = TestTestSuite.ORCHESTRATOR;

  @Before
  public void delete_data() {
    orchestrator.getDatabase().truncateInspectionTables();
  }

  @Test
  public void normal() {
    orchestrator.executeBuilds(newBuild("test/with-tests", true), newAnalysis("test/with-tests"));

    Resource project = orchestrator.getServer().getWsClient().find(ResourceQuery.createForMetrics("com.sonarsource.it.samples:with-tests",
      "coverage"));
    assertThat(project.getMeasureValue("coverage"), closeTo(66.7, 0.1));
  }

  @Test
  public void no_tests() {
    orchestrator.executeBuilds(newBuild("test/no-tests", true), newAnalysis("test/no-tests"));

    Resource project = orchestrator.getServer().getWsClient().find(ResourceQuery.createForMetrics("com.sonarsource.it.samples:no-tests",
      "coverage"));
    assertThat(project.getMeasureValue("coverage"), is(0.0));
  }

  @Test
  public void surefire_disabled() {
    orchestrator.executeBuilds(newBuild("test/disable-surefire", true), newAnalysis("test/disable-surefire"));

    Resource project = orchestrator.getServer().getWsClient().find(ResourceQuery.createForMetrics("com.sonarsource.it.samples:disable-surefire",
      "coverage"));
    assertThat(project.getMeasureValue("coverage"), is(0.0));
  }

  @Test
  public void failures_of_tests() {
    orchestrator.executeBuilds(newBuild("test/test-failures", true), newAnalysis("test/test-failures"));

    Resource project = orchestrator.getServer().getWsClient().find(ResourceQuery.createForMetrics("com.sonarsource.it.samples.test-failures:parent",
      "coverage"));
    assertThat(project.getMeasureValue("coverage"), closeTo(33.3, 0.1));
  }

  @Test
  public void test_struts() {
    orchestrator.executeBuilds(newBuild("shared/struts-1.3.9-diet", true), newAnalysis("shared/struts-1.3.9-diet"));

    Resource project = orchestrator.getServer().getWsClient().find(ResourceQuery.createForMetrics("org.apache.struts:struts-parent",
      "coverage"));
    assertThat(project.getMeasureValue("coverage"), closeTo(25.5, 0.1));

    Resource module = orchestrator.getServer().getWsClient().find(ResourceQuery.createForMetrics("org.apache.struts:struts-core",
      "coverage"));
    assertThat(module.getMeasureValue("coverage"), closeTo(37.1, 0.1));

    module = orchestrator.getServer().getWsClient().find(ResourceQuery.createForMetrics("org.apache.struts:struts-core",
      "test_success_density", "test_failures", "test_errors", "tests", "skipped_tests", "test_execution_time"));
    assertThat(module.getMeasureValue("test_success_density"), is(100.0));
    assertThat(module.getMeasureIntValue("test_failures"), is(0));
    assertThat(module.getMeasureIntValue("test_errors"), is(0));
    assertThat(module.getMeasureIntValue("tests"), is(195));
    assertThat(module.getMeasureIntValue("skipped_tests"), is(0));
    assertThat(module.getMeasureIntValue("test_execution_time"), greaterThan(10));
  }

  @Test
  public void test_integration_test_measures() {
    orchestrator.executeBuilds(newBuild("test/jacoco-integration-tests", false), newAnalysis("test/jacoco-integration-tests"));

    ResourceQuery query = ResourceQuery.createForMetrics("com.sonarsource.it.samples:jacoco-integration-tests",
      "it_coverage", "it_line_coverage", "it_branch_coverage", "it_uncovered_lines", "it_lines_to_cover");
    Resource project = orchestrator.getServer().getWsClient().find(query);
    assertThat(project.getMeasureValue("it_coverage"), closeTo(46.2, 0.1));
    assertThat(project.getMeasureValue("it_line_coverage"), closeTo(55.6, 0.1));
    assertThat(project.getMeasureValue("it_branch_coverage"), closeTo(25.0, 0.1));
    assertThat(project.getMeasureIntValue("it_uncovered_lines"), is(4));
    assertThat(project.getMeasureIntValue("it_lines_to_cover"), is(9));
  }

  /**
   * SONAR-3295
   */
  @Test
  public void excludes() {
    orchestrator.executeBuild(newBuild("test/with-tests", true));
    MavenBuild analysis = MavenBuild.builder()
      .setPom(ItUtils.locateProjectPom("test/with-tests"))
      .withDynamicAnalysis(true)
      .withProperty("sonar.java.coveragePlugin", "jacoco")
      .withProperty("sonar.jacoco.excludes", "*Hello")
      .addSonarGoal()
      .build();
    orchestrator.executeBuild(analysis);

    Resource project = orchestrator.getServer().getWsClient().find(ResourceQuery.createForMetrics("com.sonarsource.it.samples:with-tests",
      "coverage"));
    assertThat(project.getMeasureValue("coverage"), is(0.0));
  }

  /**
   * SONAR-2501
   */
  @Test
  public void should_display_coverage_per_test() {
    MavenBuild build = MavenBuild.create(ItUtils.locateProjectPom("shared/sample-with-tests"))
      .setGoals("clean test-compile");
    orchestrator.executeBuild(build);
    build.setGoals("sonar:sonar");
    orchestrator.executeBuild(build);

    Selenese selenese = Selenese.builder().setHtmlTestsInClasspath("test-display-coverage-per-test",
      "/selenium/test/display-covered-lines-per-test-in-tests-viewer.html",
      "/selenium/test/display-line-coverage-in-coverage-viewer.html",
      "/selenium/test/display-covered-lines-on-selected-test-in-coverage-viewer.html"
    ).build();
    orchestrator.executeSelenese(selenese);
  }

  private MavenBuild newBuild(String projectPath, boolean skipTests) {
    return MavenBuild.builder()
      .setPom(ItUtils.locateProjectPom(projectPath))
      .addGoal("clean install")
      .withProperty("skipTests", String.valueOf(skipTests))
      .build();
  }

  private MavenBuild newAnalysis(String projectPath) {
    return MavenBuild.builder()
      .setPom(ItUtils.locateProjectPom(projectPath))
      .withDynamicAnalysis(true)
      .withProperty("sonar.java.coveragePlugin", "jacoco")
      .addSonarGoal()
      .build();
  }

}
