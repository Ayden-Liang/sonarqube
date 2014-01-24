/*
 * Copyright (C) 2009-2012 SonarSource SA
 * All rights reserved
 * mailto:contact AT sonarsource DOT com
 */
package com.sonar.it.batch;

import com.sonar.it.ItUtils;
import com.sonar.orchestrator.Orchestrator;
import com.sonar.orchestrator.build.BuildResult;
import com.sonar.orchestrator.build.SonarRunner;
import com.sonar.orchestrator.locator.MavenLocation;
import org.junit.After;
import org.junit.ClassRule;
import org.junit.Test;
import org.sonar.wsclient.services.Resource;
import org.sonar.wsclient.services.ResourceQuery;

import static org.fest.assertions.Assertions.assertThat;

/**
 * SONAR-4069
 */
public class TaskTest {

  @ClassRule
  public static Orchestrator orchestrator = Orchestrator.builderEnv()
    .addPlugin(ItUtils.locateTestPlugin("task-plugin"))
    .addPlugin(MavenLocation.create("org.codehaus.sonar-plugins.javascript", "sonar-javascript-plugin", "1.0"))
    .addPlugin(MavenLocation.create("org.codehaus.sonar-plugins.python", "sonar-python-plugin", "1.0"))
    .build();

  @After
  public void deleteData() {
    orchestrator.getDatabase().truncateInspectionTables();
  }

  @Test
  public void test_sonar_runner_scan() {
    SonarRunner build = SonarRunner.create()
      .setProjectDir(ItUtils.locateProjectDir("batch/multi-languages"))
      .setProperty("sonar.task", "scan");
    orchestrator.executeBuild(build);

    // modules
    Resource javaModule = getResource("multi-languages:java-module", "files");
    Resource jsModule = getResource("multi-languages:javascript-module", "files");
    Resource pyModule = getResource("multi-languages:python-module", "files");
    verifyModule(javaModule, "java", 1);
    verifyModule(jsModule, "js", 1);
    verifyModule(pyModule, "py", 2);

    // project
    Resource project = getResource("multi-languages", "files");
    verifyProject(project);
  }

  @Test
  public void test_list_tasks() {
    SonarRunner build = SonarRunner.create()
      .setProjectDir(ItUtils.locateProjectDir("batch/empty-folder"))
      .setProperty("sonar.task", "list");
    BuildResult buildResult = orchestrator.executeBuild(build);

    // Check that no inspection was conducted
    assertThat(getResource("multi-languages", "files")).isNull();

    assertThat(buildResult.getLogs())
      .contains("Available tasks:")
      .contains("my-task: A simple task")
      .contains("scan: Scan project");
  }

  @Test
  public void test_component_injection_and_settings() {
    SonarRunner build = SonarRunner.create()
      .setProjectDir(ItUtils.locateProjectDir("batch/empty-folder"))
      .setProperty("sonar.task", "my-task")
      .setProperty("sonar.taskCanReadSettings", "true");
    BuildResult buildResult = orchestrator.executeBuild(build);

    assertThat(buildResult.getLogs()).contains("Executing my-task");
  }

  private void verifyModule(Resource module, String language, int files) {
    assertThat(module.getMeasureIntValue("files")).isEqualTo(files);
    assertThat(module.getLanguage()).isEqualTo(language);
  }

  private void verifyProject(Resource project) {
    verifyModule(project, "none", 4);
  }

  private Resource getResource(String resourceKey, String metricKey) {
    return orchestrator.getServer().getWsClient().find(ResourceQuery.createForMetrics(resourceKey, metricKey));
  }
}
