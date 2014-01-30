/*
 * Copyright (C) 2009-2012 SonarSource SA
 * All rights reserved
 * mailto:contact AT sonarsource DOT com
 */
package com.sonar.it.batch.suite;

import com.sonar.it.ItUtils;
import com.sonar.orchestrator.Orchestrator;
import com.sonar.orchestrator.build.BuildResult;
import com.sonar.orchestrator.build.SonarRunner;
import com.sonar.orchestrator.build.SonarRunnerInstaller;
import com.sonar.orchestrator.config.FileSystem;
import com.sonar.orchestrator.locator.FileLocation;
import com.sonar.orchestrator.version.Version;
import org.apache.commons.io.FileUtils;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.rules.TemporaryFolder;
import org.sonar.wsclient.services.Resource;
import org.sonar.wsclient.services.ResourceQuery;

import java.io.File;
import java.io.FilenameFilter;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.fest.assertions.Assertions.assertThat;

public class PreviewModeTest {

  @ClassRule
  public static Orchestrator orchestrator = BatchTestSuite.ORCHESTRATOR;

  @Rule
  public ExpectedException thrown = ExpectedException.none();

  @Rule
  public TemporaryFolder temp = new TemporaryFolder();

  private File dryRunCacheLocation;

  @Before
  public void deleteData() {
    orchestrator.getDatabase().truncateInspectionTables();
    dryRunCacheLocation = new File(new File(orchestrator.getServer().getHome(), "temp"), "dryRun");
    FileUtils.deleteQuietly(dryRunCacheLocation);
  }

  @Test
  public void test_dry_run() {
    BuildResult result = scan("shared/xoo-sample",
      "sonar.analysis.mode", "preview");

    // Analysis is not persisted in database
    Resource project = getResource("com.sonarsource.it.samples:simple-sample");
    assertThat(project).isNull();
    assertThat(result.getLogs()).contains("Preview");
    assertThat(result.getLogs()).contains("ANALYSIS SUCCESSFUL");
  }

  @Test
  public void should_not_fail_on_resources_that_have_existed_before() {
    orchestrator.getServer().restoreProfile(FileLocation.ofClasspath("/com/sonar/it/issue/IssueTest/with-many-rules.xml"));

    // First real scan with source
    scanWithProfile("shared/xoo-history-v2", "with-many-rules");
    assertThat(getResource("sample:src/main/xoo/sample/ClassAdded.xoo")).isNotNull();
    // Second scan should remove ClassAdded.xoo
    scanWithProfile("shared/xoo-history-v1", "with-many-rules");
    assertThat(getResource("sample:src/main/xoo/sample/ClassAdded.xoo")).isNull();

    // Re-add ClassAdded.xoo in local workspace
    BuildResult result = scanWithProfile("shared/xoo-history-v2", "with-many-rules",
      "sonar.analysis.mode", "preview");

    assertThat(getResource("sample:src/main/xoo/sample/ClassAdded.xoo")).isNull();
    assertThat(result.getLogs()).contains("Preview");
    assertThat(result.getLogs()).contains("ANALYSIS SUCCESSFUL");
  }

  @Test
  public void should_fail_if_plugin_access_secured_properties() {
    // Test access from task (ie BatchSettings)
    SonarRunner runner = configureRunner("shared/xoo-sample",
      "sonar.analysis.mode", "preview",
      "accessSecuredFromTask", "true");
    BuildResult result = orchestrator.executeBuildQuietly(runner);

    assertThat(result.getLogs()).contains("Access to the secured property 'foo.bar.secured' is not possible in preview mode. "
      + "The SonarQube plugin which requires this property must be deactivated in preview mode.");

    // Test access from sensor (ie ModuleSettings)
    runner = configureRunner("shared/xoo-sample",
      "sonar.analysis.mode", "preview",
      "accessSecuredFromSensor", "true");
    result = orchestrator.executeBuildQuietly(runner);

    assertThat(result.getLogs()).contains("Access to the secured property 'foo.bar.secured' is not possible in preview mode. "
      + "The SonarQube plugin which requires this property must be deactivated in preview mode.");
  }

  // SONAR-4488
  @Test
  @Ignore("1 second is enough to generate dry run DB on Jenkins so the test fail")
  public void should_fail_if_dryrun_timeout_is_too_short() {
    // Test access from task (ie BatchSettings)
    SonarRunner runner = configureRunner("shared/xoo-sample",
      "sonar.analysis.mode", "preview",
      "sonar.preview.readTimeout", "1");
    BuildResult result = orchestrator.executeBuildQuietly(runner);

    assertThat(result.getStatus()).isNotEqualTo(0);
    assertThat(result.getLogs()).contains(
      "Preview database read timed out after 1000 ms. You can try to increase read timeout with property -Dsonar.preview.readTimeout (in seconds)");
  }

  // SONAR-4468
  @Test
  public void test_build_breaker_with_dry_run() {
    orchestrator.getServer().restoreProfile(FileLocation.ofClasspath("/com/sonar/it/batch/DryRunTest/SimpleAlertProfile.xml"));
    SonarRunner runner = configureRunner("shared/xoo-sample",
      "sonar.preview.excludePlugins", "pdfreport,report,scmactivity",
      "sonar.analysis.mode", "preview")
      .setProfile("SimpleAlertProfile");
    BuildResult result = orchestrator.executeBuildQuietly(runner);

    assertThat(result.getStatus()).isNotEqualTo(0);
    assertThat(result.getLogs()).contains("[BUILD BREAKER] Lines of code > 5");
    assertThat(result.getLogs()).contains("Alert thresholds have been hit (1 times)");
  }

  // SONAR-4594
  @Test
  public void test_build_breaker_with_dry_run_and_differential_measures() {
    orchestrator.getServer().restoreProfile(FileLocation.ofClasspath("/com/sonar/it/batch/DryRunTest/VariationAlertProfile.xml"));

    // First analysis
    SonarRunner runner = configureRunner("shared/xoo-sample");
    BuildResult result = orchestrator.executeBuild(runner);

    // Second analysis
    runner = configureRunner("batch/dry-run-build-breaker",
      "sonar.preview.excludePlugins", "pdfreport,report,scmactivity",
      "sonar.analysis.mode", "preview")
      .setProfile("VariationAlertProfile");
    result = orchestrator.executeBuildQuietly(runner);

    assertThat(result.getStatus()).isNotEqualTo(0);
    assertThat(result.getLogs()).contains("[BUILD BREAKER] Lines of code variation > 2 since previous analysis");
    assertThat(result.getLogs()).contains("Alert thresholds have been hit (1 times)");
  }

  // SONAR-4594
  @Test
  public void test_build_breaker_with_dry_run_and_differential_measures_last_version() {
    orchestrator.getServer().restoreProfile(FileLocation.ofClasspath("/com/sonar/it/batch/DryRunTest/VariationSinceLastVersionAlertProfile.xml"));

    // First analysis 1.0-SNAPSHOT
    SonarRunner runner = configureRunner("shared/xoo-sample");
    orchestrator.executeBuild(runner);

    // Second analysis 2.0-SNAPSHOT
    runner = configureRunner("batch/dry-run-build-breaker",
      "sonar.preview.excludePlugins", "pdfreport,report,scmactivity",
      "sonar.analysis.mode", "preview",
      "sonar.projectVersion", "2.0-SNAPSHOT")
      .setProfile("VariationSinceLastVersionAlertProfile");
    BuildResult result = orchestrator.executeBuildQuietly(runner);

    assertThat(result.getStatus()).isNotEqualTo(0);
    assertThat(result.getLogs()).contains("[BUILD BREAKER] Lines of code variation > 2 since previous version (1.0-SNAPSHOT)");
    assertThat(result.getLogs()).contains("Alert thresholds have been hit (1 times)");
  }

  // SONAR-4602
  @Test
  public void use_dry_run_cache_on_new_project() throws Exception {
    orchestrator.getServer().restoreProfile(FileLocation.ofClasspath("/xoo/one-issue-per-line.xml"));
    // First dry run
    String profileName = "one-issue-per-line";
    SonarRunner runner = configureRunner("shared/xoo-sample",
      "sonar.analysis.mode", "preview")
      .setProfile(profileName);
    orchestrator.executeBuild(runner);

    assertThat(dryRunCacheLocation.listFiles()).onProperty("name").containsOnly("default");
    File cacheLocation = new File(dryRunCacheLocation, "default");

    assertThat(cacheLocation.listFiles(new ExcludeLockFile())).hasSize(1);
    File cachedDb = cacheLocation.listFiles(new ExcludeLockFile())[0];
    long lastModified = cachedDb.lastModified();

    // Remove quality profile using DB query to not invalidate cache to be sure
    // next analysis will use cached DB that still contain removed profile
    ItUtils.executeUpdate(orchestrator, "DELETE FROM rules_profiles WHERE name = '" + profileName + "'");

    // Second dry run should not fail event if profile was removed from DB
    runner = configureRunner("shared/xoo-sample",
      "sonar.analysis.mode", "preview")
      .setProfile(profileName);
    orchestrator.executeBuild(runner);

    assertThat(cachedDb.lastModified()).isEqualTo(lastModified);
  }

  // SONAR-4602
  @Test
  public void use_dry_run_cache_on_existing_project() throws Exception {
    orchestrator.getServer().restoreProfile(FileLocation.ofClasspath("/xoo/one-issue-per-line.xml"));
    // First run (not dry run)
    String profileName = "one-issue-per-line";
    SonarRunner runner = configureRunner("shared/xoo-sample")
      .setProfile(profileName);
    orchestrator.executeBuild(runner);

    // First dry run
    runner = configureRunner("shared/xoo-sample",
      "sonar.analysis.mode", "preview")
      .setProfile(profileName);
    orchestrator.executeBuild(runner);

    // Here we can't guess project id
    assertThat(dryRunCacheLocation.listFiles(new ExcludeLockFile())).hasSize(1);
    File cacheLocation = dryRunCacheLocation.listFiles(new ExcludeLockFile())[0];
    assertThat(cacheLocation.getName()).isNotEqualTo("default");

    assertThat(cacheLocation.listFiles(new ExcludeLockFile())).hasSize(1);
    File cachedDb = cacheLocation.listFiles(new ExcludeLockFile())[0];
    long lastModified = cachedDb.lastModified();

    // Remove quality profile using DB query to not invalidate cache to be sure
    // next analysis will use cached DB that still contain removed profile
    ItUtils.executeUpdate(orchestrator, "DELETE FROM rules_profiles WHERE name = '" + profileName + "'");

    // Second dry run should not fail event if profile was removed from DB
    runner = configureRunner("shared/xoo-sample",
      "sonar.analysis.mode", "preview")
      .setProfile(profileName);
    orchestrator.executeBuild(runner);

    assertThat(cachedDb.lastModified()).isEqualTo(lastModified);
  }

  // SONAR-4602
  @Test
  public void evict_dry_run_cache_after_new_analysis() throws Exception {
    orchestrator.getServer().restoreProfile(FileLocation.ofClasspath("/xoo/one-issue-per-line.xml"));
    // First run (not dry run)
    SonarRunner runner = configureRunner("shared/xoo-sample")
      .setProfile("empty");
    orchestrator.executeBuild(runner);

    // First dry run
    runner = configureRunner("shared/xoo-sample",
      "sonar.analysis.mode", "preview")
      .setProfile("one-issue-per-line");
    BuildResult result = orchestrator.executeBuild(runner);

    // As many new issue as lines
    assertThat(ItUtils.countIssuesInJsonReport(result, true)).isEqualTo(13);

    // Second run (not dry run) should invalidate cache
    runner = configureRunner("shared/xoo-sample")
      .setProfile("one-issue-per-line");
    orchestrator.executeBuild(runner);

    // Second dry run
    runner = configureRunner("shared/xoo-sample",
      "sonar.analysis.mode", "preview")
      .setProfile("one-issue-per-line");
    result = orchestrator.executeBuild(runner);

    // No new issue this time
    assertThat(ItUtils.countIssuesInJsonReport(result, true)).isEqualTo(0);
  }

  // SONAR-4602
  @Test
  public void evict_dry_run_cache_after_profile_change() throws Exception {
    orchestrator.getServer().restoreProfile(FileLocation.ofClasspath("/com/sonar/it/batch/DryRunTest/one-issue-per-line-empty.xml"));
    // First run (not dry run)
    SonarRunner runner = configureRunner("shared/xoo-sample")
      .setProfile("one-issue-per-line");
    orchestrator.executeBuild(runner);

    // First dry run
    runner = configureRunner("shared/xoo-sample",
      "sonar.analysis.mode", "preview")
      .setProfile("one-issue-per-line");
    BuildResult result = orchestrator.executeBuild(runner);

    // No new issues
    assertThat(ItUtils.countIssuesInJsonReport(result, true)).isEqualTo(0);

    // Modification of QP should invalidate cache
    orchestrator.getServer().restoreProfile(FileLocation.ofClasspath("/xoo/one-issue-per-line.xml"));

    // Second dry run
    runner = configureRunner("shared/xoo-sample",
      "sonar.analysis.mode", "preview")
      .setProfile("one-issue-per-line");
    result = orchestrator.executeBuild(runner);

    // As many new issue as lines
    assertThat(ItUtils.countIssuesInJsonReport(result, true)).isEqualTo(13);
  }

  // SONAR-4602
  @Test
  public void evict_dry_run_cache_after_issue_change() throws Exception {
    orchestrator.getServer().restoreProfile(FileLocation.ofClasspath("/xoo/one-issue-per-line.xml"));
    // First run (not dry run)
    SonarRunner runner = configureRunner("shared/xoo-sample")
      .setProfile("one-issue-per-line");
    orchestrator.executeBuild(runner);

    // First dry run
    runner = configureRunner("shared/xoo-sample",
      "sonar.analysis.mode", "preview")
      .setProfile("one-issue-per-line");
    BuildResult result = orchestrator.executeBuild(runner);

    // 13 issues
    assertThat(ItUtils.countIssuesInJsonReport(result, false)).isEqualTo(13);

    // Flag one issue as false positive
    JSONObject obj = ItUtils.getJSONReport(result);
    String key = ((JSONObject) ((JSONArray) obj.get("issues")).get(0)).get("key").toString();
    ItUtils.newWsClientForAdmin(orchestrator).issueClient().doTransition(key, "falsepositive");

    // Second dry run
    runner = configureRunner("shared/xoo-sample",
      "sonar.analysis.mode", "preview")
      .setProfile("one-issue-per-line");
    result = orchestrator.executeBuild(runner);

    // False positive is not returned
    assertThat(ItUtils.countIssuesInJsonReport(result, false)).isEqualTo(12);
  }

  // SONAR-4602
  @Test
  public void concurrent_dry_run_access_cache_on_new_project() throws Exception {
    orchestrator.getServer().restoreProfile(FileLocation.ofClasspath("/xoo/one-issue-per-line.xml"));
    runConcurrentDryRun();
  }

  // SONAR-4602
  @Test
  public void concurrent_dry_run_access_cache_on_existing_project() throws Exception {
    orchestrator.getServer().restoreProfile(FileLocation.ofClasspath("/xoo/one-issue-per-line.xml"));
    SonarRunner runner = configureRunner("shared/xoo-sample")
      .setProfile("one-issue-per-line");
    orchestrator.executeBuild(runner);

    runConcurrentDryRun();
  }

  private void runConcurrentDryRun() throws InterruptedException, ExecutionException {
    // Install sonar-runner in advance to avoid concurrent unzip issues
    FileSystem fileSystem = orchestrator.getConfiguration().fileSystem();
    new SonarRunnerInstaller(fileSystem).install(Version.create(SonarRunner.DEFAULT_RUNNER_VERSION), fileSystem.workspace());
    final int nThreads = 5;
    final String profileName = "one-issue-per-line";
    ExecutorService executorService = Executors.newFixedThreadPool(nThreads);
    List<Callable<BuildResult>> tasks = new ArrayList<Callable<BuildResult>>();
    for (int i = 0; i < nThreads; i++) {
      tasks.add(new Callable<BuildResult>() {

        public BuildResult call() throws Exception {
          SonarRunner runner = configureRunner("shared/xoo-sample",
            "sonar.working.directory", temp.newFolder().getAbsolutePath(),
            "sonar.analysis.mode", "preview")
            .setProfile(profileName);
          return orchestrator.executeBuild(runner);
        }
      });
    }

    for (Future<BuildResult> result : executorService.invokeAll(tasks)) {
      result.get();
    }
  }

  private Resource getResource(String key) {
    return orchestrator.getServer().getWsClient().find(ResourceQuery.createForMetrics(key, "lines"));
  }

  private BuildResult scan(String projectPath, String... props) {
    SonarRunner runner = configureRunner(projectPath, props);
    return orchestrator.executeBuild(runner);
  }

  private BuildResult scanWithProfile(String projectPath, String profile, String... props) {
    SonarRunner runner = configureRunner(projectPath, props).setProfile(profile);
    return orchestrator.executeBuild(runner);
  }

  private SonarRunner configureRunner(String projectPath, String... props) {
    SonarRunner runner = SonarRunner.create(ItUtils.locateProjectDir(projectPath))
      .setProperties(props);
    return runner;
  }

  public static class ExcludeLockFile implements FilenameFilter {
    public boolean accept(File dir, String name) {
      return !name.contains(".lock");
    }
  }

}
