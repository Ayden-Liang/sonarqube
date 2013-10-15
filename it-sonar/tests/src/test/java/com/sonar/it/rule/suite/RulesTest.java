/*
 * Copyright (C) 2009-2012 SonarSource SA
 * All rights reserved
 * mailto:contact AT sonarsource DOT com
 */

package com.sonar.it.rule.suite;

import com.sonar.orchestrator.Orchestrator;
import com.sonar.orchestrator.selenium.Selenese;
import org.junit.ClassRule;
import org.junit.Test;

public class RulesTest {

  @ClassRule
  public static Orchestrator orchestrator = RuleTestSuite.ORCHESTRATOR;


  /**
   * SONAR-4193
   */
  @Test
  public void display_link_to_to_another_rule_in_description_rule() {
    orchestrator.executeSelenese(Selenese
      .builder()
      .setHtmlTestsInClasspath("should_display_link_to_to_another_rule_in_description_rule",
        "/selenium/rule/show-rule/display-link-to-another-rule-in-description-rule.html"
      ).build());
  }
}
