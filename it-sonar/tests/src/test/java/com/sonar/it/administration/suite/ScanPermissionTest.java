/*
 * Copyright (C) 2009-2012 SonarSource SA
 * All rights reserved
 * mailto:contact AT sonarsource DOT com
 */

package com.sonar.it.administration.suite;

import com.sonar.it.ItUtils;
import com.sonar.orchestrator.Orchestrator;
import com.sonar.orchestrator.build.BuildResult;
import com.sonar.orchestrator.build.SonarRunner;
import com.sonar.orchestrator.selenium.Selenese;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.sonar.wsclient.SonarClient;
import org.sonar.wsclient.permissions.PermissionParameters;
import org.sonar.wsclient.user.UserParameters;

import static org.fest.assertions.Assertions.assertThat;

/**
 * SONAR-4397
 */
public class ScanPermissionTest {

  private final static String USER_LOGIN = "scanperm";

  @ClassRule
  public static Orchestrator orchestrator = AdministrationTestSuite.ORCHESTRATOR;
  private static SonarClient client;

  @BeforeClass
  public static void createUser() {
    client = ItUtils.newWsClientForAdmin(orchestrator);

    UserParameters userCreationParameters = UserParameters.create().login(USER_LOGIN).name(USER_LOGIN).password("thewhite").passwordConfirmation("thewhite");
    client.userClient().create(userCreationParameters);
  }

  @Before
  public void cleanup() {
    orchestrator.getDatabase().truncateInspectionTables();
  }

  @After
  public void restorePermissions() {
    PermissionParameters permissionParameters = PermissionParameters.create().group("anyone").permission("scan");
    client.permissionClient().addPermission(permissionParameters);

    permissionParameters = PermissionParameters.create().group("anyone").permission("dryRunScan");
    client.permissionClient().addPermission(permissionParameters);
  }

  @AfterClass
  public static void dropUser() {
    client.userClient().deactivate(USER_LOGIN);
  }

  @Test
  public void should_fail_if_no_scan_role() throws Exception {
    SonarRunner build = SonarRunner.create()
        .setRunnerVersion("2.2.1")
        .setProperty("sonar.login", USER_LOGIN)
        .setProperty("sonar.password", "thewhite")
        .setProjectDir(ItUtils.locateProjectDir("shared/xoo-sample"));
    orchestrator.executeBuild(build);
    // No error

    // Remove Anyone from scan permission
    PermissionParameters permissionParameters = PermissionParameters.create().group("anyone").permission("scan");
    client.permissionClient().removePermission(permissionParameters);

    BuildResult result = orchestrator.executeBuildQuietly(build);
    assertThat(result.getStatus()).isNotEqualTo(0);
    assertThat(result.getLogs()).contains(
        "You're only authorized to execute a local (dry run) SonarQube analysis without pushing the results to the SonarQube server. Please contact your SonarQube administrator.");

    // Remove Anyone from dryrun permission
    permissionParameters = PermissionParameters.create().group("anyone").permission("dryRunScan");
    client.permissionClient().removePermission(permissionParameters);

    result = orchestrator.executeBuildQuietly(build);
    assertThat(result.getStatus()).isNotEqualTo(0);
    assertThat(result.getLogs()).contains("You're not authorized to execute any SonarQube analysis. Please contact your SonarQube administrator.");
  }

  @Test
  public void should_not_fail_if_no_project_role() throws Exception {
    // Do a first analysis
    SonarRunner build = SonarRunner.create()
        .setRunnerVersion("2.2.1")
        .setProperty("sonar.login", USER_LOGIN)
        .setProperty("sonar.password", "thewhite")
        .setProjectDir(ItUtils.locateProjectDir("shared/xoo-sample"));
    orchestrator.executeBuild(build);
    // No error

    // Remove all groups from project users
    Selenese selenese = Selenese.builder()
        .setHtmlTestsInClasspath("remove_project_user_roles",
            "/selenium/administration/remove-project-user-roles/remove_project_user_roles.html"
        ).build();
    orchestrator.executeSelenese(selenese);

    orchestrator.executeBuild(build);
    // No error
  }

}
