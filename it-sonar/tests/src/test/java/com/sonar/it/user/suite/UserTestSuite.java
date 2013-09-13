/*
 * Copyright (C) 2009-2012 SonarSource SA
 * All rights reserved
 * mailto:contact AT sonarsource DOT com
 */
package com.sonar.it.user.suite;

import com.sonar.it.ItUtils;
import com.sonar.orchestrator.Orchestrator;
import org.junit.ClassRule;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;

@RunWith(Suite.class)
@Suite.SuiteClasses({
  UserAdministrationTest.class
})
public class UserTestSuite {

  @ClassRule
  public static final Orchestrator ORCHESTRATOR = Orchestrator.builderEnv()

    // used by UserAdministrationTest
    .addPlugin(ItUtils.locateTestPlugin("user-handler-plugin"))

    .build();
}
