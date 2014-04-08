/*
 * Copyright (C) 2009-2014 SonarSource SA
 * All rights reserved
 * mailto:contact AT sonarsource DOT com
 */
package com.sonar.it.server;

import com.sonar.orchestrator.Orchestrator;
import com.sonar.orchestrator.selenium.Selenese;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.util.EntityUtils;
import org.fest.assertions.Assertions;
import org.json.simple.JSONValue;
import org.junit.ClassRule;
import org.junit.Test;
import org.sonar.wsclient.services.Server;
import org.sonar.wsclient.services.ServerQuery;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import static org.fest.assertions.Assertions.assertThat;
import static org.junit.Assert.fail;


public class ServerAdministrationTest {

  @ClassRule
  public static Orchestrator orchestrator = Orchestrator.createEnv();

  @Test
  public void get_sonar_version() {
    String version = orchestrator.getServer().getWsClient().find(new ServerQuery()).getVersion();
    if (!StringUtils.startsWithAny(version, new String[]{"3.7", "4."})) {
      fail("Bad version: " + version);
    }
  }

  @Test
  public void get_server_status() {
    Assertions.assertThat(orchestrator.getServer().getWsClient().find(new ServerQuery()).getStatus()).isEqualTo(Server.Status.UP);
  }

  @Test
  public void generate_server_id() {
    Selenese selenese = Selenese.builder().setHtmlTestsInClasspath("server_id",
      "/selenium/server_id/missing_ip.html",
      // SONAR-4102
      "/selenium/server_id/organisation_must_not_accept_special_chars.html",
      "/selenium/server_id/valid_id.html").build();
    orchestrator.executeSelenese(selenese);
  }

  @Test
  public void display_system_info() {
    Selenese selenese = Selenese.builder().setHtmlTestsInClasspath("server-administration",
      "/selenium/server/server-administration/system_info.html"
    ).build();
    orchestrator.executeSelenese(selenese);
  }

  /**
   * SONAR-3147
   */
  @Test
  public void test_widgets_web_service() throws IOException {
    HttpClient httpclient = new DefaultHttpClient();
    try {
      HttpGet get = new HttpGet(orchestrator.getServer().getUrl() + "/api/widgets");
      HttpResponse response = httpclient.execute(get);

      assertThat(response.getStatusLine().getStatusCode()).isEqualTo(200);
      String json = IOUtils.toString(response.getEntity().getContent());
      List widgets = (List) JSONValue.parse(json);
      assertThat(widgets.size()).isGreaterThan(10);

      // quick test of the first widget
      assertThat(((Map) widgets.get(0)).get("title")).isNotNull();

      EntityUtils.consume(response.getEntity());

    } finally {
      httpclient.getConnectionManager().shutdown();
    }
  }

  /**
   * SONAR-5197
   */
  @Test
  public void api_ws_shortcut() throws Exception {
    HttpClient httpclient = new DefaultHttpClient();
    try {
      HttpGet get = new HttpGet(orchestrator.getServer().getUrl() + "/api");
      HttpResponse response = httpclient.execute(get);

      assertThat(response.getStatusLine().getStatusCode()).isEqualTo(200);
      String json = IOUtils.toString(response.getEntity().getContent());
      Map jsonAsMap = (Map) JSONValue.parse(json);
      assertThat(jsonAsMap.get("webServices")).isNotNull();
      EntityUtils.consume(response.getEntity());

    } finally {
      httpclient.getConnectionManager().shutdown();
    }
  }
}
