/*
 * Copyright (C) 2009-2012 SonarSource SA
 * All rights reserved
 * mailto:contact AT sonarsource DOT com
 */
package com.sonar.it.administration.suite;

import com.sonar.it.ItUtils;
import com.sonar.orchestrator.Orchestrator;
import com.sonar.orchestrator.build.MavenBuild;
import com.sonar.orchestrator.locator.FileLocation;
import com.sonar.orchestrator.selenium.Selenese;
import org.junit.After;
import org.junit.ClassRule;
import org.junit.Test;
import org.sonar.wsclient.connectors.ConnectionException;
import org.sonar.wsclient.services.ProjectDeleteQuery;
import org.sonar.wsclient.services.PropertyQuery;
import org.sonar.wsclient.services.ResourceQuery;

import javax.annotation.Nullable;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.Calendar;
import java.util.GregorianCalendar;

import static org.fest.assertions.Assertions.assertThat;

public class ProjectAdministrationTest {

  @ClassRule
  public static Orchestrator orchestrator = AdministrationTestSuite.ORCHESTRATOR;

  private static final String PROJECT_KEY = "com.sonarsource.it.samples:simple-sample";
  private static final String FILE_KEY = "com.sonarsource.it.samples:simple-sample:sample.Sample";

  @After
  public void deleteAnalysisData() throws SQLException {
    orchestrator.getDatabase().truncateInspectionTables();

    executeSql("DELETE FROM group_roles WHERE resource_id IS NOT NULL");
    executeSql("DELETE FROM user_roles WHERE resource_id IS NOT NULL");
  }

  private void executeSql(String sql) {
    Connection connection = orchestrator.getDatabase().openConnection();
    try {
      connection.prepareStatement(sql).execute();
      // commit is useless on some databases
      connection.commit();
    } catch (SQLException e) {
      // frequent use-case : the table does not exist
    } finally {
      orchestrator.getDatabase().closeQuietly(connection);
    }
  }

  @Test
  public void should_delete_project_by_web_service() {
    scanSampleWithDate("2012-01-01");

    assertThat(orchestrator.getServer().getWsClient().find(ResourceQuery.create(PROJECT_KEY))).isNotNull();
    assertThat(orchestrator.getServer().getWsClient().find(ResourceQuery.create(FILE_KEY))).isNotNull();

    orchestrator.getServer().getAdminWsClient().delete(ProjectDeleteQuery.create(PROJECT_KEY));

    assertThat(orchestrator.getServer().getWsClient().find(ResourceQuery.create(PROJECT_KEY))).isNull();
    assertThat(orchestrator.getServer().getWsClient().find(ResourceQuery.create(FILE_KEY))).isNull();
  }

  @Test(expected = ConnectionException.class)
  public void should_delete_only_projects() {
    scanSampleWithDate("2012-01-01");

    assertThat(orchestrator.getServer().getWsClient().find(ResourceQuery.create(PROJECT_KEY))).isNotNull();
    assertThat(orchestrator.getServer().getWsClient().find(ResourceQuery.create(FILE_KEY))).isNotNull();

    // it's forbidden to delete only some files
    orchestrator.getServer().getAdminWsClient().delete(ProjectDeleteQuery.create(FILE_KEY));
  }

  @Test(expected = ConnectionException.class)
  public void admin_role_should_be_required_to_delete_project() {
    scanSampleWithDate("2012-01-01");

    assertThat(orchestrator.getServer().getWsClient().find(ResourceQuery.create(PROJECT_KEY))).isNotNull();

    // use getWsClient() instead of getAdminWsClient()
    orchestrator.getServer().getWsClient().delete(ProjectDeleteQuery.create(PROJECT_KEY));
  }

  /**
   * Test updated for SONAR-3570
   */
  @Test
  public void test_project_deletion() throws Exception {
    // This test must be done separately as the project will be deleted, so no other test can be done afterwards
    scanSampleWithDate("2012-01-01");
    Selenese selenese = Selenese.builder().setHtmlTestsInClasspath("project-deletion", "/selenium/administration/project-deletion/project-deletion.html").build();
    orchestrator.executeSelenese(selenese);
  }

  @Test
  public void test_project_administration() throws Exception {
    GregorianCalendar today = new GregorianCalendar();
    scanSampleWithDate((today.get(Calendar.YEAR) - 1) + "-01-01");
    scanSampleWithDate(today.get(Calendar.YEAR) + "-01-01");// The analysis must be run once again to have an history so that it is possible
                                                            // to
    // delete a snapshot
    Selenese selenese = Selenese
        .builder()
        .setHtmlTestsInClasspath("project-administration",
            "/selenium/administration/project-administration/project-exclusions.html",
            "/selenium/administration/project-administration/project-general-exclusions.html",
            "/selenium/administration/project-administration/project-test-exclusions.html",
            "/selenium/administration/project-administration/project-general-test-exclusions.html",
            "/selenium/administration/project-administration/project-links.html",
            "/selenium/administration/project-administration/project-modify-versions.html",
            "/selenium/administration/project-administration/project-rename-current-version.html",
            "/selenium/administration/project-administration/project-history-deletion.html", // SONAR-3206
            "/selenium/administration/project-administration/project-quality-profile.html" // SONAR-3517
        ).build();
    orchestrator.executeSelenese(selenese);
  }

  // SONAR-3326
  @Test
  public void should_display_alerts_correctly_in_history_page() throws Exception {
    // with this configuration, project should have an Orange alert
    orchestrator.getServer().restoreProfile(FileLocation.ofClasspath("/com/sonar/it/administration/ProjectAdministrationTest/low-alert-thresholds-profile-backup.xml"));
    scanSample("2012-01-01", "alert-profile");
    // with this configuration, project should have a Green alert
    orchestrator.getServer().restoreProfile(FileLocation.ofClasspath("/com/sonar/it/administration/ProjectAdministrationTest/high-alert-thresholds-profile-backup.xml"));
    scanSample("2012-01-02", "alert-profile");

    Selenese selenese = Selenese
        .builder()
        .setHtmlTestsInClasspath("display-alerts-history-page",
            "/selenium/administration/display-alerts-history-page/should-display-alerts-correctly-history-page.html"
        ).build();
    orchestrator.executeSelenese(selenese);
  }

  // SONAR-1352
  @Test
  public void should_display_period_alert_on_project_dashboard() throws Exception {
    // No alert
    orchestrator.getServer().restoreProfile(FileLocation.ofClasspath("/com/sonar/it/administration/ProjectAdministrationTest/period-alert-thresholds-profile-backup.xml"));
    scanSample("2012-01-01", "alert-profile");

    // Red alert because lines number has not changed since previous analysis
    orchestrator.getServer().restoreProfile(FileLocation.ofClasspath("/com/sonar/it/administration/ProjectAdministrationTest/period-alert-thresholds-profile-backup.xml"));
    scanSampleWithProfile("alert-profile");

    Selenese selenese = Selenese
        .builder()
        .setHtmlTestsInClasspath("display-period-alerts",
            "/selenium/administration/display-alerts/should-display-period-alerts-correctly.html"
        ).build();
    orchestrator.executeSelenese(selenese);
  }

  /**
   * SONAR-3425
   */
  @Test
  public void project_settings() {
    scanSampleWithDate("2012-01-01");

    Selenese selenese = Selenese.builder().setHtmlTestsInClasspath("project-settings",
        // SONAR-3425
        "/selenium/administration/project-settings/override-global-settings.html"
        ).build();
    orchestrator.executeSelenese(selenese);

    assertThat(orchestrator.getServer().getAdminWsClient().find(PropertyQuery.createForResource("sonar.skippedModules", "com.sonarsource.it.samples:simple-sample")).getValue())
        .isEqualTo("my-excluded-module");
  }

  /**
   * SONAR-1608
   */
  @Test
  public void should_bulk_update_project_keys() {
    MavenBuild build = MavenBuild.builder()
        .setPom(ItUtils.locateProjectPom("shared/multi-modules-sample"))
        .addSonarGoal()
        .withDynamicAnalysis(false)
        .build();
    orchestrator.executeBuild(build);

    Selenese selenese = Selenese
        .builder()
        .setHtmlTestsInClasspath("project-bulk-update-keys",
            "/selenium/administration/project-update-keys/bulk-update-impossible-because-duplicate-keys.html",
            "/selenium/administration/project-update-keys/bulk-update-impossible-because-no-input.html",
            "/selenium/administration/project-update-keys/bulk-update-impossible-because-no-match.html",
            "/selenium/administration/project-update-keys/bulk-update-success.html"
        ).build();
    orchestrator.executeSelenese(selenese);
  }

  /**
   * SONAR-1608
   */
  @Test
  public void should_fine_grain_update_project_keys() {
    MavenBuild build = MavenBuild.builder()
        .setPom(ItUtils.locateProjectPom("shared/multi-modules-sample"))
        .addSonarGoal()
        .withDynamicAnalysis(false)
        .build();
    orchestrator.executeBuild(build);

    Selenese selenese = Selenese
        .builder()
        .setHtmlTestsInClasspath("project-fine-grained-update-keys",
            "/selenium/administration/project-update-keys/fine-grained-update-impossible.html",
            "/selenium/administration/project-update-keys/fine-grained-update-success.html"
        ).build();
    orchestrator.executeSelenese(selenese);
  }

  /**
   * SONAR-3956
   */
  @Test
  public void manage_project_roles() {
    scanSample();

    Selenese selenese = Selenese
        .builder()
        .setHtmlTestsInClasspath("manage_project_roles",
            "/selenium/administration/manage_project_roles/change_roles_of_users.html",
            "/selenium/administration/manage_project_roles/change_roles_of_groups.html"
        ).build();
    orchestrator.executeSelenese(selenese);
  }

  /**
   * SONAR-4050
   */
  @Test
  public void do_not_reset_default_project_roles() {
    scanSample();

    Selenese selenese = Selenese.builder()
        .setHtmlTestsInClasspath("do_not_reset_default_roles_1",
            "/selenium/administration/do_not_reset_default_roles/1_set_project_roles.html"
        ).build();
    orchestrator.executeSelenese(selenese);

    scanSample();

    selenese = Selenese.builder()
        .setHtmlTestsInClasspath("do_not_reset_default_roles_2",
            "/selenium/administration/do_not_reset_default_roles/2_project_roles_are_unchanged.html"
        ).build();
    orchestrator.executeSelenese(selenese);
  }

  @Test
  public void anonymous_should_have_user_role_to_access_project() {
    scanSample();

    Selenese selenese = Selenese.builder()
        .setHtmlTestsInClasspath("anonymous_should_have_user_role_to_access_project",
            "/selenium/administration/anonymous_should_have_user_role_to_access_project/remove_user_role.html"
        ).build();
    orchestrator.executeSelenese(selenese);
  }

  /**
   * SONAR-4060
   */
  @Test
  public void should_display_module_settings() {
    orchestrator.executeBuild(MavenBuild.create(ItUtils.locateProjectPom("maven/modules-declaration"))
        .setCleanSonarGoals()
        .setProperty("sonar.dynamicAnalysis", "false"));

    Selenese selenese = Selenese.builder().setHtmlTestsInClasspath("module-settings",
        // SONAR-3425
        "/selenium/administration/module-settings/display-module-settings.html"
        ).build();
    orchestrator.executeSelenese(selenese);
  }

  private void scanSample(@Nullable String date, @Nullable String profile) {
    MavenBuild build = MavenBuild.create(ItUtils.locateProjectPom("shared/sample"))
        .setCleanSonarGoals()
        .setProperty("sonar.dynamicAnalysis", "false");
    if (date != null) {
      build.setProperty("sonar.projectDate", date);
    }
    if (profile != null) {
      build.setProperty("sonar.profile", profile);
    }
    orchestrator.executeBuild(build);
  }

  private void scanSampleWithProfile(String profile) {
    scanSample(null, profile);
  }

  private void scanSampleWithDate(String date) {
    scanSample(date, null);
  }

  private void scanSample() {
    scanSample(null, null);
  }

}
