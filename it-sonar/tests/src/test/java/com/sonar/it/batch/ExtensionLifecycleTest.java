/*
 * Copyright (C) 2009-2012 SonarSource SA
 * All rights reserved
 * mailto:contact AT sonarsource DOT com
 */
package com.sonar.it.batch;

import com.sonar.it.ItUtils;
import com.sonar.orchestrator.Orchestrator;
import com.sonar.orchestrator.build.MavenBuild;
import com.sonar.orchestrator.locator.MavenLocation;
import org.junit.ClassRule;
import org.junit.Test;

public class ExtensionLifecycleTest {

  @ClassRule
  public static Orchestrator orchestrator = Orchestrator.builderEnv()
    .addPlugin(ItUtils.locateTestPlugin("extension-lifecycle-plugin"))
    .build();

  @Test
  public void testInstantiationStrategyAndLifecycleOfBatchExtensions() {
    MavenBuild build = MavenBuild.builder()
      .setPom(ItUtils.locateProjectPom("batch/extension-lifecycle"))
      .addSonarGoal()
      .withDynamicAnalysis(false)
      .build();

    // Build fails if the extensions provided in the extension-lifecycle-plugin are not correctly
    // managed.
    orchestrator.executeBuild(build);
  }
}
