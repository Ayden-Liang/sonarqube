/*
 * Copyright (C) 2009-2012 SonarSource SA
 * All rights reserved
 * mailto:contact AT sonarsource DOT com
 */
package com.sonar.it.server;

import com.sonar.it.ItUtils;
import com.sonar.orchestrator.Orchestrator;
import com.sonar.orchestrator.selenium.Selenese;
import org.apache.commons.lang.StringUtils;
import org.junit.ClassRule;
import org.junit.Test;
import org.sonar.wsclient.services.Plugin;
import org.sonar.wsclient.services.UpdateCenterQuery;

import java.util.List;

import static junit.framework.Assert.assertNotNull;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.number.OrderingComparisons.greaterThan;
import static org.junit.Assert.assertThat;

public class UpdateCenterTest {

  @ClassRule
  public static Orchestrator orchestrator = Orchestrator.builderEnv()
    .setServerProperty("sonar.updatecenter.url", UpdateCenterTest.class.getResource("/com/sonar/it/server/UpdateCenterTest/update-center.properties").toString())
    .addPlugin(ItUtils.locateTestPlugin("sonar-fake-plugin"))
    .build();

  @Test
  public void web_service_should_return_installed_plugins() {
    List<Plugin> plugins = orchestrator.getServer().getAdminWsClient().findAll(UpdateCenterQuery.createForInstalledPlugins());
    assertThat(plugins.size(), greaterThan(0));

    Plugin installedPlugin = findPlugin(plugins, "fake");
    assertNotNull(installedPlugin);
    assertThat(installedPlugin.getName(), is("Plugins :: Fake"));
    assertThat(installedPlugin.getVersion(), is("1.0-SNAPSHOT"));
  }

  @Test
  public void test_console() {
    Selenese selenese = Selenese.builder().setHtmlTestsInClasspath("server-update-center",
      "/selenium/server/updatecenter/installed-plugins.html",
      "/selenium/server/updatecenter/plugin-updates.html",
      "/selenium/server/updatecenter/refresh-update-center.html",
      "/selenium/server/updatecenter/system-updates.html",
      "/selenium/server/updatecenter/available-plugins.html"
    ).build();
    orchestrator.executeSelenese(selenese);
  }

  private Plugin findPlugin(List<Plugin> plugins, String pluginKey) {
    for (Plugin plugin : plugins) {
      if (StringUtils.equals(pluginKey, plugin.getKey())) {
        return plugin;
      }
    }
    return null;
  }

}
