/*
 * Copyright (C) 2009-2012 SonarSource SA
 * All rights reserved
 * mailto:contact AT sonarsource DOT com
 */
package com.sonar.it.issue;

import com.sonar.it.ItUtils;
import com.sonar.orchestrator.Orchestrator;
import com.sonar.orchestrator.build.SonarRunner;
import com.sonar.orchestrator.locator.FileLocation;
import com.sonar.orchestrator.selenium.Selenese;
import com.sonar.orchestrator.util.NetworkUtils;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.sonar.wsclient.Sonar;
import org.sonar.wsclient.issue.BulkChangeQuery;
import org.sonar.wsclient.issue.Issue;
import org.sonar.wsclient.issue.IssueClient;
import org.sonar.wsclient.issue.IssueQuery;
import org.sonar.wsclient.issue.Issues;
import org.sonar.wsclient.services.PropertyUpdateQuery;
import org.subethamail.wiser.Wiser;
import org.subethamail.wiser.WiserMessage;

import javax.mail.internet.MimeMessage;

import java.util.Iterator;

import static org.fest.assertions.Assertions.assertThat;

public class NotificationsTest {

  @ClassRule
  public static Orchestrator orchestrator = Orchestrator.builderEnv()
    .addPlugin(ItUtils.xooPlugin())
    .restoreProfileAtStartup(FileLocation.ofClasspath("/xoo/one-issue-per-line.xml"))
    // 1 second
    .setServerProperty("sonar.notifications.delay", "1")
    .build();

  private static Wiser smtpServer;

  private IssueClient issueClient;

  @BeforeClass
  public static void before() throws Exception {
    smtpServer = new Wiser(NetworkUtils.getNextAvailablePort());
    smtpServer.start();
    System.out.println("SMTP Server port: " + smtpServer.getServer().getPort());

    // Configure Sonar
    Sonar wsClient = orchestrator.getServer().getAdminWsClient();
    wsClient.update(new PropertyUpdateQuery("email.smtp_host.secured", "localhost"));
    wsClient.update(new PropertyUpdateQuery("email.smtp_port.secured", Integer.toString(smtpServer.getServer().getPort())));

    // 1. Check that SMTP server was turned on and able to send test email
    // 2. Create user, which will receive notifications for new violations
    Selenese selenese = Selenese
      .builder()
      .setHtmlTestsInClasspath("notifications",
        "/selenium/issue/notification/email_configuration.html",
        "/selenium/issue/notification/create_user_with_email.html").build();
    orchestrator.executeSelenese(selenese);
  }

  @AfterClass
  public static void stop() {
    if (smtpServer != null) {
      smtpServer.stop();
    }
  }

  @Before
  public void prepare() {
    orchestrator.getDatabase().truncateInspectionTables();
    SonarRunner build = SonarRunner.create(ItUtils.locateProjectDir("issue/notifications"))
      .setProperty("sonar.projectDate", "2011-12-15")
      .setProperty("sonar.profile", "one-issue-per-line");
    orchestrator.executeBuild(build);

    issueClient = orchestrator.getServer().adminWsClient().issueClient();
  }

  @Test
  public void notifications_for_new_issues_and_issue_changes() throws Exception {
    // change assignee
    Issues issues = issueClient.find(IssueQuery.create().componentRoots("sample-notifications"));
    Issue issue = issues.list().get(0);
    issueClient.assign(issue.key(), "tester");

    // We need to wait until all notifications will be delivered
    Thread.sleep(10000);

    Iterator<WiserMessage> emails = smtpServer.getMessages().iterator();

    MimeMessage message = emails.next().getMimeMessage();
    assertThat(message.getHeader("To", null)).isEqualTo("<test@example.org>");
    assertThat((String) message.getContent()).contains("This is a test message from SonarQube");

    assertThat(emails.hasNext()).isTrue();
    message = emails.next().getMimeMessage();
    assertThat(message.getHeader("To", null)).isEqualTo("<tester@example.org>");
    assertThat((String) message.getContent()).contains("Sample project for notifications");
    assertThat((String) message.getContent()).contains("13 new issues");
    assertThat((String) message.getContent()).contains("Blocker: 0   Critical: 0   Major: 13   Minor: 0   Info: 0");
    assertThat((String) message.getContent()).contains(
      "See it in SonarQube: http://localhost:9000/issues/search?componentRoots=sample-notifications&createdAt=2011-12-15T00%3A00%3A00%2B0100");

    assertThat(emails.hasNext()).isTrue();
    message = emails.next().getMimeMessage();
    assertThat(message.getHeader("To", null)).isEqualTo("<tester@example.org>");
    assertThat((String) message.getContent()).contains("sample/Sample.xoo");
    assertThat((String) message.getContent()).contains("Assignee changed to Tester");
    assertThat((String) message.getContent()).contains("See it in SonarQube: http://localhost:9000/issue/show/" + issue.key());

    assertThat(emails.hasNext()).isFalse();
  }

  /**
   * SONAR-4606
   */
  @Test
  public void notifications_for_bulk_change_ws() throws Exception {

    Issues issues = issueClient.find(IssueQuery.create().componentRoots("sample-notifications"));
    Issue issue = issues.list().get(0);

    // bulk change without notification by default
    issueClient.bulkChange(BulkChangeQuery.create().issues(issue.key())
      .actions("assign", "set_severity")
      .actionParameter("assign", "assignee", "tester")
      .actionParameter("set_severity", "severity", "MINOR"));

    // bulk change with notification
    issueClient.bulkChange(BulkChangeQuery.create().issues(issue.key())
      .actions("set_severity")
      .actionParameter("set_severity", "severity", "BLOCKER")
      .sendNotifications(true));

    // We need to wait until all notifications will be delivered
    Thread.sleep(10000);

    Iterator<WiserMessage> emails = smtpServer.getMessages().iterator();

    MimeMessage message = emails.next().getMimeMessage();
    assertThat(message.getHeader("To", null)).isEqualTo("<test@example.org>");
    assertThat((String) message.getContent()).contains("This is a test message from SonarQube");

    assertThat(emails.hasNext()).isTrue();
    message = emails.next().getMimeMessage();
    assertThat(message.getHeader("To", null)).isEqualTo("<tester@example.org>");
    assertThat((String) message.getContent()).contains("Sample project for notifications");
    assertThat((String) message.getContent()).contains("13 new issues");
    assertThat((String) message.getContent()).contains("Blocker: 0   Critical: 0   Major: 13   Minor: 0   Info: 0");
    assertThat((String) message.getContent()).contains(
      "See it in SonarQube: http://localhost:9000/issues/search?componentRoots=sample-notifications&createdAt=2011-12-15T00%3A00%3A00%2B0100");

    assertThat(emails.hasNext()).isTrue();
    message = emails.next().getMimeMessage();
    assertThat(message.getHeader("To", null)).isEqualTo("<tester@example.org>");
    assertThat((String) message.getContent()).contains("sample/Sample.xoo");
    assertThat((String) message.getContent()).contains("Severity: BLOCKER (was MINOR)");
    assertThat((String) message.getContent()).contains("See it in SonarQube: http://localhost:9000/issue/show/" + issue.key());

    assertThat(emails.hasNext()).isFalse();
  }

  /**
   * SONAR-4606
   */
  @Test
  public void notifications_for_bulk_change_from_console() throws Exception {
    orchestrator.executeSelenese(Selenese.builder().setHtmlTestsInClasspath("should_apply_bulk_change_from_console",
      "/selenium/issue/notification/bulk-change.html"
      ).build());

    // We need to wait until all notifications will be delivered
    Thread.sleep(10000);

    Iterator<WiserMessage> emails = smtpServer.getMessages().iterator();

    MimeMessage message = emails.next().getMimeMessage();
    assertThat(message.getHeader("To", null)).isEqualTo("<test@example.org>");
    assertThat((String) message.getContent()).contains("This is a test message from SonarQube");

    assertThat(emails.hasNext()).isTrue();
    message = emails.next().getMimeMessage();
    assertThat(message.getHeader("To", null)).isEqualTo("<tester@example.org>");
    assertThat((String) message.getContent()).contains("Sample project for notifications");
    assertThat((String) message.getContent()).contains("13 new issues");
    assertThat((String) message.getContent()).contains("Blocker: 0   Critical: 0   Major: 13   Minor: 0   Info: 0");
    assertThat((String) message.getContent()).contains(
      "See it in SonarQube: http://localhost:9000/issues/search?componentRoots=sample-notifications&createdAt=2011-12-15T00%3A00%3A00%2B0100");

    // One email per changed issue
    for (int i = 0; i < 13; i++) {
      assertThat(emails.hasNext()).isTrue();
      message = emails.next().getMimeMessage();
      assertThat(message.getHeader("To", null)).isEqualTo("<tester@example.org>");
      assertThat((String) message.getContent()).contains("sample/Sample.xoo");
      assertThat((String) message.getContent()).contains("Severity: BLOCKER (was MINOR)");
    }

    assertThat(emails.hasNext()).isFalse();
  }

}
