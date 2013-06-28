/*
 * Copyright (C) 2009-2013 SonarSource SA
 * All rights reserved
 * mailto:contact AT sonarsource DOT com
 */
package com.sonar.license.it;

import com.sonar.orchestrator.Orchestrator;
import com.sonar.orchestrator.build.BuildResult;
import com.sonar.orchestrator.build.MavenBuild;
import com.sonar.orchestrator.locator.FileLocation;
import org.apache.commons.io.IOUtils;
import org.junit.Rule;
import org.junit.Test;
import org.sonar.wsclient.services.Property;
import org.sonar.wsclient.services.PropertyDeleteQuery;
import org.sonar.wsclient.services.PropertyQuery;
import org.sonar.wsclient.services.PropertyUpdateQuery;

import java.io.File;

import static org.fest.assertions.Assertions.assertThat;

public class LicenseTest {

  @Rule
  public Orchestrator orchestrator = Orchestrator.builderEnv()
      .addPlugin(FileLocation.of("../plugins/sonar-faux-sqale-plugin/target/sonar-faux-sqale-plugin-1.0-SNAPSHOT.jar"))
      .build();

  @Test
  public void batch_must_log_error_and_ignore_bad_license() {
    // no license is set
    orchestrator.getServer().getAdminWsClient().update(new PropertyUpdateQuery()
        .setKey("sonar.sqale.license.secured")
        .setValue(""));

    // server-side components are not secured when there are no licenses
    // -> they are always up
    Property serverProperty = orchestrator.getServer().getWsClient().find(PropertyQuery.createForKey("printed_from_server_extension"));
    assertThat(serverProperty.getValue()).isEqualTo("true");

    // batch-side components are secured
    MavenBuild build = MavenBuild.create(new File("projects/java-sample/pom.xml")).setCleanSonarGoals();
    BuildResult result = orchestrator.executeBuild(build);
    if (LicenseVersion.isGreaterThanOrEqualTo(orchestrator, "2.3")) {
      assertThat(result.getLogs()).contains("No license for plugin sqale");
    } else {
      assertThat(result.getLogs()).contains("No valid license for plugin sqale");
    }
    assertThat(result.getLogs()).excludes("-- BIP BIP --");
  }

  @Test
  public void set_valid_license_without_restarting_server() {
    String validLicense = orchestrator.plugins().licenses().get("sqale");
    orchestrator.getServer().getAdminWsClient().update(new PropertyUpdateQuery()
        .setKey("sonar.sqale.license.secured")
        .setValue(validLicense));

    MavenBuild build = MavenBuild.create(new File("projects/java-sample/pom.xml")).setCleanSonarGoals();
    BuildResult result = orchestrator.executeBuild(build);
    if (LicenseVersion.isGreaterThanOrEqualTo(orchestrator, "2.3")) {
      assertThat(result.getLogs()).excludes("No license for plugin sqale");
    } else {
      assertThat(result.getLogs()).excludes("No valid license for plugin sqale");
    }
    assertThat(result.getLogs()).contains("sqale plugin licensed to");
    assertThat(result.getLogs()).contains("-- BIP BIP --");
  }

  // LICENSE-23
  @Test
  public void test_expired_license() throws Exception {
    String expiredLicense = IOUtils.toString(this.getClass().getResourceAsStream("/sqale_prod_2013-05-29_allserver.txt"));
    orchestrator.getServer().getAdminWsClient().update(new PropertyUpdateQuery()
        .setKey("sonar.sqale.license.secured")
        .setValue(expiredLicense));

    // batch-side components are secured
    MavenBuild build = MavenBuild.create(new File("projects/java-sample/pom.xml")).setCleanSonarGoals();
    BuildResult result = orchestrator.executeBuild(build);
    if (LicenseVersion.isGreaterThanOrEqualTo(orchestrator, "2.3")) {
      assertThat(result.getLogs()).contains("License for plugin sqale is expired");
    } else {
      assertThat(result.getLogs()).contains("No valid license for plugin sqale");
    }
    assertThat(result.getLogs()).excludes("-- BIP BIP --");
  }

  // LICENSE-23
  @Test
  public void test_license_wrong_server_id() throws Exception {
    String wrongLicense = IOUtils.toString(this.getClass().getResourceAsStream("/sqale_prod_2030-01-01_123456789123456.txt"));
    orchestrator.getServer().getAdminWsClient().update(new PropertyUpdateQuery()
        .setKey("sonar.sqale.license.secured")
        .setValue(wrongLicense));

    // batch-side components are secured
    MavenBuild build = MavenBuild.create(new File("projects/java-sample/pom.xml")).setCleanSonarGoals();
    BuildResult result = orchestrator.executeBuild(build);
    if (LicenseVersion.isGreaterThanOrEqualTo(orchestrator, "2.3")) {
      assertThat(result.getLogs()).contains("License for plugin sqale does not match server ID. Please check settings.");
    } else {
      assertThat(result.getLogs()).contains("No valid license for plugin sqale");
    }
    assertThat(result.getLogs()).excludes("-- BIP BIP --");
  }

  // LICENSE-23
  @Test
  public void test_license_invalid_server_id() throws Exception {
    // Store current value to restore at the end
    Property previousId = orchestrator.getServer().getAdminWsClient().find(new PropertyQuery()
        .setKey("sonar.server_id"));

    try {
      // What if user try to modify server ID
      orchestrator.getServer().getAdminWsClient().update(new PropertyUpdateQuery()
          .setKey("sonar.server_id")
          .setValue("123456789123456"));

      String wrongLicense = IOUtils.toString(this.getClass().getResourceAsStream("/sqale_prod_2030-01-01_123456789123456.txt"));
      orchestrator.getServer().getAdminWsClient().update(new PropertyUpdateQuery()
          .setKey("sonar.sqale.license.secured")
          .setValue(wrongLicense));

      // batch-side components are secured
      MavenBuild build = MavenBuild.create(new File("projects/java-sample/pom.xml")).setCleanSonarGoals();
      BuildResult result = orchestrator.executeBuild(build);
      if (LicenseVersion.isGreaterThanOrEqualTo(orchestrator, "2.3")) {
        assertThat(result.getLogs()).contains("Server ID is invalid. Please check settings.");
      } else {
        assertThat(result.getLogs()).contains("No valid license for plugin sqale");
      }
      assertThat(result.getLogs()).excludes("-- BIP BIP --");

    } finally {
      // Restore old ID
      if (previousId != null) {
        orchestrator.getServer().getAdminWsClient().update(new PropertyUpdateQuery()
            .setKey("sonar.server_id")
            .setValue(previousId.getValue()));
      }
      else {
        orchestrator.getServer().getAdminWsClient().delete(new PropertyDeleteQuery("sonar.server_id"));
      }
    }
  }
}
