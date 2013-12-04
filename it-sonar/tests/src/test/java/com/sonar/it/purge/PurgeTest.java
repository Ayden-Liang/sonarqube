/*
 * Copyright (C) 2009-2012 SonarSource SA
 * All rights reserved
 * mailto:contact AT sonarsource DOT com
 */

package com.sonar.it.purge;

import com.sonar.it.ItUtils;
import com.sonar.orchestrator.Orchestrator;
import com.sonar.orchestrator.build.MavenBuild;
import com.sonar.orchestrator.locator.FileLocation;
import org.apache.commons.lang.time.DateFormatUtils;
import org.apache.commons.lang.time.DateUtils;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;

import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.fest.assertions.Assertions.assertThat;

public class PurgeTest {

  @ClassRule
  public static Orchestrator orchestrator = Orchestrator.builderEnv()
    .restoreProfileAtStartup(FileLocation.ofClasspath("/sonar-way-2.7.xml"))
    .build();

  @Before
  public void deleteProjectData() {
    orchestrator.getDatabase().truncateInspectionTables();
  }

  @Test
  public void test_evolution_of_number_of_rows_when_scanning_two_times_the_same_project() {
    Date today = new Date();
    Date yesterday = DateUtils.addDays(today, -1);

    scan("shared/struts-1.3.9-diet", DateFormatUtils.ISO_DATE_FORMAT.format(yesterday));

    // count components
    assertThat(count("projects where qualifier in ('TRK','BRC')")).as("Wrong number of projects").isEqualTo(4);
    assertThat(count("projects where qualifier in ('PAC')")).as("Wrong number of packages").isEqualTo(31);
    assertThat(count("projects where qualifier in ('CLA')")).as("Wrong number of files").isEqualTo(320);
    assertThat(count("projects where qualifier in ('UTS')")).as("Wrong number of unit test files").isEqualTo(28);

    int measuresOnTrk = 199;
    int measuresOnBrc = 456;
    int measuresOnPac = 2619;
    int measuresOnCla = 14683;
    int measuresOnUts = 28;

    // count measures 
    measures("TRK", measuresOnTrk);
    measures("BRC", measuresOnBrc);
    measures("PAC", measuresOnPac);
    measures("CLA", measuresOnCla);
    measures("UTS", measuresOnUts);

    // No new_* metrics measure should be recorded the first time
    assertThat(count("project_measures, metrics where metrics.id = project_measures.metric_id and metrics.name like 'new_%'"))
      .as("Wrong number of measure of new_ metrics")
      .isEqualTo(0);

    int expectedMeasures = measuresOnTrk + measuresOnBrc + measuresOnPac + measuresOnCla + measuresOnUts;
    assertThat(count("project_measures")).as("Wrong number of measures").isEqualTo(expectedMeasures);
    assertThat(count("measure_data")).as("Wrong number of measure_data").isEqualTo(1157);

    // count other tables that are constant between 2 scans
    int expectedIssues = 4000;
    int expectedSources = 348;
    int expectedDependencies = 977;
    assertThat(count("snapshot_sources")).as("Wrong number of snapshot_sources").isEqualTo(expectedSources);

    assertThat(count("issues")).as("Wrong number of issues").isEqualTo(expectedIssues);
    assertThat(count("dependencies")).as("Wrong number of dependencies").isEqualTo(expectedDependencies);

    // must be a different date, else a single snapshot is kept per day
    scan("shared/struts-1.3.9-diet", DateFormatUtils.ISO_DATE_FORMAT.format(today));

    int newMeasuresOnTrk = 143;
    int newMeasuresOnBrc = 356;
    int newMeasuresOnPac = 531;
    int newMeasuresOnCla = 0;
    int newMeasuresOnUts = 0;

    measures("TRK", measuresOnTrk + newMeasuresOnTrk);
    measures("BRC", measuresOnBrc + newMeasuresOnBrc);
    measures("PAC", measuresOnPac + newMeasuresOnPac);
    measures("CLA", measuresOnCla + newMeasuresOnCla);
    measures("UTS", measuresOnUts + newMeasuresOnUts);

    // Measures on new_* metrics should be recorded
    assertThat(count("project_measures, metrics where metrics.id = project_measures.metric_id and metrics.name like 'new_%'"))
      .as("Wrong number of measure of new_ metrics")
      .isEqualTo(735);

    // added measures relate to project and new_* metrics
    expectedMeasures += newMeasuresOnTrk + newMeasuresOnBrc + newMeasuresOnPac + newMeasuresOnCla + newMeasuresOnUts;
    assertThat(count("project_measures")).as("Wrong number of measures after second analysis").isEqualTo(expectedMeasures);

    assertThat(count("snapshot_sources")).as("Wrong number of snapshot_sources").isEqualTo(expectedSources);
    assertThat(count("measure_data")).as("Wrong number of measure_data").isEqualTo(1161);
    assertThat(count("issues")).as("Wrong number of issues").isEqualTo(expectedIssues);
    assertThat(count("dependencies")).as("Wrong number of dependencies").isEqualTo(expectedDependencies);
  }

  /**
   * SONAR-3378
   */
  @Test
  public void should_keep_all_snapshots_the_first_day() {

    // analyse once
    scan("shared/sample");
    // analyse twice
    scan("shared/sample");
    // and check we have 2 snapshots
    assertThat(count("snapshots s where s.project_id=(select p.id from projects p where p.kee='com.sonarsource.it.samples:simple-sample')")).isEqualTo(2);
  }

  /**
   * SONAR-2807 & SONAR-3378 & SONAR-4710
   */
  @Test
  public void should_keep_only_one_snapshot_per_day() {

    scan("shared/struts-1.3.9-diet");

    int snapshotsCount = count("snapshots where qualifier<>'LIB'");
    int measuresCount = count("project_measures");
    // Using the "sonar.dbcleaner.hoursBeforeKeepingOnlyOneSnapshotByDay" property set to '0' is the way
    // to keep only 1 snapshot per day
    scan("shared/struts-1.3.9-diet", "sonar.dbcleaner.hoursBeforeKeepingOnlyOneSnapshotByDay", "0");
    assertThat(count("snapshots where qualifier<>'LIB'")).as("Different number of snapshots").isEqualTo(snapshotsCount);

    int measureOnNewMetrics = count("project_measures, metrics where metrics.id = project_measures.metric_id and metrics.name like 'new_%'");
    // Number of measures should be the same as previous, with the measures on new metrics
    assertThat(count("project_measures")).as("Different number of measures").isEqualTo(measuresCount + measureOnNewMetrics);
  }

  /**
   * SONAR-3120
   */
  @Test
  public void should_delete_removed_modules() {

    scan("purge/modules/before");
    assertSingleSnapshot("com.sonarsource.it.samples.purge:module_b");
    assertSingleSnapshot("com.sonarsource.it.samples.purge:module_b1");

    // we want the previous snapshot to be purged
    scan("purge/modules/after", "sonar.dbcleaner.hoursBeforeKeepingOnlyOneSnapshotByDay", "0");
    assertDeleted("com.sonarsource.it.samples.purge:module_b");
    assertDeleted("com.sonarsource.it.samples.purge:module_b1");
    assertSingleSnapshot("com.sonarsource.it.samples.purge:module_c");
  }

  /**
   * SONAR-3120
   */
  @Test
  public void should_delete_removed_files() {

    scan("purge/files/before");
    assertSingleSnapshot("com.sonarsource.it.samples.purge:files:sample.Sample");
    assertSingleSnapshot("com.sonarsource.it.samples.purge:files:sample.Sample");

    scan("purge/files/after");
    assertDeleted("com.sonarsource.it.samples.purge:files:sample.Sample");
    assertDeleted("com.sonarsource.it.samples.purge:files:sample.Sample");
    assertSingleSnapshot("com.sonarsource.it.samples.purge:files:sample.NewSample");
  }

  /**
   * SONAR-2754
   */
  @Test
  public void should_delete_historical_data_of_directories_by_default() {

    scan("shared/sample", "2012-01-01");
    String select = "snapshots where scope='DIR'";
    int directorySnapshots = count(select);

    scan("shared/sample", "2012-02-02");
    assertThat(count(select)).isEqualTo(directorySnapshots);
  }

  /**
   * SONAR-2754
   */
  @Test
  public void should_not_delete_historical_data_of_directories() {
    scan("shared/sample", "2012-01-01");

    String select = "snapshots where scope='DIR'";
    int directorySnapshots = count(select);

    MavenBuild build = MavenBuild.create(ItUtils.locateProjectPom("shared/sample"))
      .setCleanSonarGoals()
      .setProperty("sonar.dynamicAnalysis", "false")
      .setProfile("sonar-way-2.7")
      .setProperty("sonar.projectDate", "2012-02-02")
      .setProperty("sonar.dbcleaner.cleanDirectory", "false");
    orchestrator.executeBuild(build);

    assertThat(count(select)).isEqualTo(2 * directorySnapshots);
  }

  /**
   * SONAR-2061
   */
  @Test
  public void should_delete_historical_data_of_flagged_metrics() {

    scan("shared/sample", "2012-01-01");

    // historical data of complexity_in_classes is supposed to be deleted (see CoreMetrics)
    String selectNcloc = "project_measures where metric_id in (select id from metrics where name='ncloc')";
    String selectComplexityInClasses = "project_measures where metric_id in (select id from metrics where name='complexity_in_classes')";
    int nclocCount = count(selectNcloc);
    int complexitInClassesCount = count(selectComplexityInClasses);

    scan("shared/sample", "2012-02-02");
    assertThat(count(selectNcloc)).isGreaterThan(nclocCount);
    assertThat(count(selectComplexityInClasses)).isEqualTo(complexitInClassesCount);
  }

  private void assertDeleted(String key) {
    assertThat(count("snapshots s where s.project_id=(select p.id from projects p where p.kee='" + key + "')")).isZero();
    assertThat(count("resource_index ri where ri.resource_id=(select p.id from projects p where p.kee='" + key + "')")).isZero();
  }

  private void assertSingleSnapshot(String key) {
    assertThat(count("snapshots s where s.project_id=(select p.id from projects p where p.kee='" + key + "')")).isEqualTo(1);
    assertThat(count("resource_index ri where ri.resource_id=(select p.id from projects p where p.kee='" + key + "')")).isGreaterThan(1);
  }

  private MavenBuild scan(String path, String date) {
    return scan(path, "sonar.projectDate", date);
  }

  private MavenBuild scan(String path, String... extraProperties) {
    MavenBuild build = MavenBuild.create(ItUtils.locateProjectPom(path))
      .setCleanPackageSonarGoals()
      .setProperty("skipTests", "true")
      .setProfile("sonar-way-2.7");
    if (extraProperties != null) {
      build.setProperties(extraProperties);
    }
    orchestrator.executeBuild(build);
    return build;
  }

  private int count(String condition) {
    return orchestrator.getDatabase().countSql("select count(*) from " + condition);
  }

  private int measures(String qualifier, int count) {
    int result = countMeasures(qualifier);
    if (result != count) {
      logMeasures(qualifier);
      assertThat(result).isEqualTo(count);
    }
    return result;
  }

  private int countMeasures(String qualifier) {
    String sql = "SELECT count(pm.id) FROM project_measures pm, snapshots s, metrics m where pm.snapshot_id=s.id and pm.metric_id=m.id and s.qualifier='" + qualifier + "'";
    return orchestrator.getDatabase().countSql(sql);
  }

  private void logMeasures(String qualifier) {
    String sql = "SELECT m.name as metricName, pm.value as value, pm.text_value as textValue, pm.variation_value_1, pm.variation_value_2, pm.variation_value_3, pm.rule_id, pm.characteristic_id "
      +
      "FROM project_measures pm, snapshots s, metrics m " +
      "WHERE pm.snapshot_id=s.id and pm.metric_id=m.id and s.qualifier='"
      + qualifier + "'";
    List<Map<String, String>> rows = orchestrator.getDatabase().executeSql(sql);

    System.out.println("---- measures on qualifier = [" + qualifier + "]");
    for (Map<String, String> row : rows) {
      System.out.println("  " + row);
    }
  }

}
