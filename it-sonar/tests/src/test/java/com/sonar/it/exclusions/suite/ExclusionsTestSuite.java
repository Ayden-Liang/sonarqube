/*
 * Copyright (C) 2009-2014 SonarSource SA
 * All rights reserved
 * mailto:contact AT sonarsource DOT com
 */
package com.sonar.it.exclusions.suite;

import com.sonar.it.ItUtils;
import com.sonar.orchestrator.Orchestrator;
import org.junit.ClassRule;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;

@RunWith(Suite.class)
@Suite.SuiteClasses({
  FileExclusionsTest.class, IssueExclusionsTest.class, SourceFiltersTest.class, CoverageExclusionsTest.class
})
public class ExclusionsTestSuite {

  @ClassRule
  public static final Orchestrator ORCHESTRATOR = Orchestrator.builderEnv()
    .addPlugin(ItUtils.xooPlugin())
    .setOrchestratorProperty("javaVersion","LATEST_RELEASE").addPlugin("java")
    .build();
}
