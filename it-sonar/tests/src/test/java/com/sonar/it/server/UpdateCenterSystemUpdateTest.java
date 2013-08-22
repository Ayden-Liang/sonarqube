/*
 * Copyright (C) 2009-2012 SonarSource SA
 * All rights reserved
 * mailto:contact AT sonarsource DOT com
 */
package com.sonar.it.server;

import com.sonar.it.ItUtils;
import com.sonar.orchestrator.Orchestrator;
import com.sonar.orchestrator.selenium.Selenese;
import org.junit.After;
import org.junit.Test;

import java.io.IOException;

public class UpdateCenterSystemUpdateTest {

  private Orchestrator orchestrator;

  @After
  public void stop() {
    if (orchestrator != null) {
      orchestrator.stop();
      orchestrator = null;
    }
  }

  /**
   * SONAR-4279
   */
  @Test
  public void should_not_display_already_compatible_plugins_on_system_update() {
    orchestrator = Orchestrator.builderEnv()
      .setServerProperty("sonar.updatecenter.url",
        UpdateCenterSystemUpdateTest.class.getResource(
          "/com/sonar/it/server/UpdateCenterTest/update-center-system-update-with-already-compatible-plugins.properties").toString())
      .addPlugin(ItUtils.locateTestPlugin("sonar-fake-plugin"))
      .build();

    orchestrator.start();
    Selenese selenese = Selenese.builder().setHtmlTestsInClasspath("system-updates-without-plugin-updates",
      "/selenium/server/updatecenter/system-updates-without-plugin-updates.html"
    ).build();
    orchestrator.executeSelenese(selenese);
  }

  /**
   * SONAR-4585
   */
  @Test
  public void should_system_update_page_not_fail_when_installed_plugin_version_not_found_in_update_center_definitions() throws IOException {
    orchestrator = Orchestrator.builderEnv()
      .setServerProperty("sonar.updatecenter.url",
        UpdateCenterSystemUpdateTest.class.getResource(
          "/com/sonar/it/server/UpdateCenterTest/update-center-with-missing-plugin-version.properties").toString())
      .addPlugin(ItUtils.locateTestPlugin("sonar-fake-plugin"))
      .build();

    orchestrator.start();

    Selenese selenese = Selenese.builder().setHtmlTestsInClasspath("system-updates-with-missing-installed-plugin-version",
      "/selenium/server/updatecenter/system-updates-with-missing-installed-plugin-version.html"
    ).build();
    orchestrator.executeSelenese(selenese);
  }

}
