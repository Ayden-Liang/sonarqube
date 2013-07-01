/*
 * Copyright (C) 2009-2012 SonarSource SA
 * All rights reserved
 * mailto:contact AT sonarsource DOT com
 */
package com.sonar.it.issue.suite;

import com.sonar.it.ItUtils;
import com.sonar.orchestrator.build.MavenBuild;
import com.sonar.orchestrator.locator.FileLocation;
import org.junit.Before;
import org.junit.Test;
import org.sonar.wsclient.issue.Issue;
import org.sonar.wsclient.issue.IssueQuery;

import java.util.List;

import static org.fest.assertions.Assertions.assertThat;

public class IssuePurgeTest extends AbstractIssueTestCase {

  @Before
  public void deleteAnalysisData() {
    orchestrator.getDatabase().truncateInspectionTables();
  }

  /**
   * SONAR-4308
   */
  @Test
  public void should_delete_all_closed_issues() throws Exception {
    orchestrator.getServer().restoreProfile(FileLocation.ofClasspath("/sonar-way-2.7.xml"));

    // Generate some issues
    MavenBuild scan = MavenBuild.create(ItUtils.locateProjectPom("shared/sample"))
      .setCleanSonarGoals()
      .setProfile("sonar-way-2.7");
    orchestrator.executeBuilds(scan);

    // All the issues are open
    List<Issue> issues = search(IssueQuery.create()).list();
    for (Issue issue : issues) {
      assertThat(issue.resolution()).isNull();
    }

    // Second scan with empty profile -> all issues are resolve and closed -> deleted by purge because property value is zero
    scan = MavenBuild.create(ItUtils.locateProjectPom("shared/sample"))
      .setCleanSonarGoals()
      .setProperty("sonar.dbcleaner.daysBeforeDeletingClosedIssues", "0")
      .setProfile("empty");
    orchestrator.executeBuilds(scan);
    issues = search(IssueQuery.create()).list();
    assertThat(issues).isEmpty();
  }

  /**
   * SONAR-4308
   */
  @Test
  public void should_purge_old_closed_issues() throws Exception {
    orchestrator.getServer().restoreProfile(FileLocation.ofClasspath("/sonar-way-2.7.xml"));

    // Generate some issues
    MavenBuild scan = MavenBuild.create(ItUtils.locateProjectPom("shared/sample"))
      .setCleanSonarGoals()
      .setProperty("sonar.projectDate", "2010-01-01")
      .setProfile("sonar-way-2.7");
    orchestrator.executeBuilds(scan);

    // All the issues are open
    List<Issue> issues = search(IssueQuery.create()).list();
    for (Issue issue : issues) {
      assertThat(issue.resolution()).isNull();
    }

    // Second scan with empty profile -> all issues are resolve and closed
    // -> Not delete because less than 30 days long
    scan = MavenBuild.create(ItUtils.locateProjectPom("shared/sample"))
      .setCleanSonarGoals()
      .setProperty("sonar.dbcleaner.daysBeforeDeletingClosedIssues", "30")
      .setProperty("sonar.projectDate", "2010-01-10")
      .setProfile("empty");
    orchestrator.executeBuilds(scan);
    issues = search(IssueQuery.create()).list();
    for (Issue issue : issues) {
      assertThat(issue.resolution()).isNotNull();
      assertThat(issue.status()).isEqualTo("CLOSED");
    }

    // Third scan much later -> closed issues are deleted
    scan = MavenBuild.create(ItUtils.locateProjectPom("shared/sample"))
      .setCleanSonarGoals()
      .setProperty("sonar.dbcleaner.daysBeforeDeletingClosedIssues", "30")
      .setProperty("sonar.projectDate", "2013-01-10")
      .setProfile("empty");
    orchestrator.executeBuilds(scan);
    issues = search(IssueQuery.create()).list();
    assertThat(issues.isEmpty());
  }
}
