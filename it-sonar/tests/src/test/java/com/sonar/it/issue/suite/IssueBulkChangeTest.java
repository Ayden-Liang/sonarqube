/*
 * Copyright (C) 2009-2012 SonarSource SA
 * All rights reserved
 * mailto:contact AT sonarsource DOT com
 */

package com.sonar.it.issue.suite;

import com.google.common.base.Function;
import com.google.common.collect.Iterables;
import com.sonar.it.ItUtils;
import com.sonar.orchestrator.build.SonarRunner;
import com.sonar.orchestrator.locator.FileLocation;
import com.sonar.orchestrator.selenium.Selenese;
import org.junit.Before;
import org.junit.Test;
import org.sonar.wsclient.issue.*;

import java.util.List;

import static com.google.common.collect.Lists.newArrayList;
import static org.fest.assertions.Assertions.assertThat;

/**
 * SONAR-4421
 */
public class IssueBulkChangeTest extends AbstractIssueTestCase {

  @Before
  public void resetData() {
    orchestrator.getDatabase().truncateInspectionTables();
  }

  @Test
  public void should_change_severity() {
    analyzeSampleProjectWillSmallNumberOfIssues();
    String newSeverity = "BLOCKER";
    int nbIssues = 3;
    String[] issueKeys = getIssueKeys(search(IssueQuery.create()).list(), nbIssues);

    BulkChange bulkChange = adminIssueClient().bulkChange(
      BulkChangeQuery.create()
        .issues(issueKeys)
        .actions("set_severity")
        .actionParameter("set_severity", "severity", newSeverity)
    );
    assertThat(bulkChange.totalIssuesChanged()).isEqualTo(nbIssues);
    for (Issue issue : search(IssueQuery.create().issues(issueKeys)).list()) {
      assertThat(issue.severity()).isEqualTo(newSeverity);
    }
  }

  @Test
  public void should_do_transition() {
    analyzeSampleProjectWillSmallNumberOfIssues();
    int nbIssues = 3;
    String[] issueKeys = getIssueKeys(search(IssueQuery.create()).list(), nbIssues);
    BulkChange bulkChange = adminIssueClient().bulkChange(
      BulkChangeQuery.create()
        .issues(issueKeys)
        .actions("do_transition")
        .actionParameter("do_transition", "transition", "confirm")
    );

    assertThat(bulkChange.totalIssuesChanged()).isEqualTo(nbIssues);
    for (Issue issue : search(IssueQuery.create().issues(issueKeys)).list()) {
      assertThat(issue.status()).isEqualTo("CONFIRMED");
    }
  }

  @Test
  public void should_assign() {
    analyzeSampleProjectWillSmallNumberOfIssues();
    int nbIssues = 3;
    String[] issueKeys = getIssueKeys(search(IssueQuery.create()).list(), nbIssues);
    BulkChange bulkChange = adminIssueClient().bulkChange(
      BulkChangeQuery.create()
        .issues(issueKeys)
        .actions("assign")
        .actionParameter("assign", "assignee", "admin")
    );

    assertThat(bulkChange.totalIssuesChanged()).isEqualTo(nbIssues);
    for (Issue issue : search(IssueQuery.create().issues(issueKeys)).list()) {
      assertThat(issue.assignee()).isEqualTo("admin");
    }
  }

  @Test
  public void should_plan() {
    analyzeSampleProjectWillSmallNumberOfIssues();

    // Create action plan
    ActionPlan newActionPlan = adminActionPlanClient().create(
      NewActionPlan.create().name("Short term").project("sample").description("Short term issues").deadLine(ItUtils.toDate("2113-01-31")));

    int nbIssues = 3;
    String[] issueKeys = getIssueKeys(search(IssueQuery.create()).list(), nbIssues);
    BulkChange bulkChange = adminIssueClient().bulkChange(
      BulkChangeQuery.create()
        .issues(issueKeys)
        .actions("plan")
        .actionParameter("plan", "plan", newActionPlan.key())
    );

    assertThat(bulkChange.totalIssuesChanged()).isEqualTo(nbIssues);
    for (Issue issue : search(IssueQuery.create().issues(issueKeys)).list()) {
      assertThat(issue.actionPlan()).isEqualTo(newActionPlan.key());
    }
  }

  @Test
  public void should_add_comment() {
    analyzeSampleProjectWillSmallNumberOfIssues();
    String newSeverity = "BLOCKER";
    int nbIssues = 3;
    String[] issueKeys = getIssueKeys(search(IssueQuery.create()).list(), nbIssues);

    BulkChange bulkChange = adminIssueClient().bulkChange(
      BulkChangeQuery.create()
        .issues(issueKeys)
        .actions("set_severity", "comment")
        .actionParameter("set_severity", "severity", newSeverity)
        .actionParameter("comment", "comment", "this is my *comment*")
    );
    assertThat(bulkChange.totalIssuesChanged()).isEqualTo(nbIssues);
    for (Issue issue : search(IssueQuery.create().issues(issueKeys)).list()) {
      assertThat(issue.comments()).hasSize(1);
      assertThat(issue.comments().get(0).htmlText()).isEqualTo("this is my <em>comment</em>");
    }
  }

  @Test
  public void should_apply_bulk_change_on_many_actions() {
    analyzeSampleProjectWillSmallNumberOfIssues();
    String newSeverity = "BLOCKER";
    int nbIssues = 3;
    String[] issueKeys = getIssueKeys(search(IssueQuery.create()).list(), nbIssues);
    BulkChange bulkChange = adminIssueClient().bulkChange(
      BulkChangeQuery.create()
        .issues(issueKeys)
        .actions("do_transition", "assign", "set_severity")
        .actionParameter("do_transition", "transition", "confirm")
        .actionParameter("assign", "assignee", "admin")
        .actionParameter("set_severity", "severity", newSeverity)
        .comment("this is my *comment*")
    );

    assertThat(bulkChange.totalIssuesChanged()).isEqualTo(nbIssues);
    for (Issue issue : search(IssueQuery.create().issues(issueKeys)).list()) {
      assertThat(issue.status()).isEqualTo("CONFIRMED");
      assertThat(issue.assignee()).isEqualTo("admin");
      assertThat(issue.severity()).isEqualTo(newSeverity);
      assertThat(issue.comments()).hasSize(1);
      assertThat(issue.comments().get(0).htmlText()).isEqualTo("this is my <em>comment</em>");
    }
  }

  @Test
  public void should_not_apply_bulk_change_if_not_logged() {
    analyzeSampleProjectWillSmallNumberOfIssues();
    String newSeverity = "BLOCKER";
    int nbIssues = 3;
    String[] issueKeys = getIssueKeys(search(IssueQuery.create()).list(), nbIssues);

    BulkChangeQuery query = (BulkChangeQuery.create().issues(issueKeys).actions("set_severity").actionParameter("set_severity", "severity", newSeverity));
    try {
      issueClient().bulkChange(query);
    } catch (Exception e) {
      verifyHttpException(e, 401);
    }
  }

  @Test
  public void should_not_apply_bulk_change_if_no_change_to_do() {
    analyzeSampleProjectWillSmallNumberOfIssues();
    String newSeverity = "BLOCKER";
    int nbIssues = 3;
    String[] issueKeys = getIssueKeys(search(IssueQuery.create()).list(), nbIssues);

    // Apply the bulk change a first time
    BulkChangeQuery query = (BulkChangeQuery.create().issues(issueKeys).actions("set_severity").actionParameter("set_severity", "severity", newSeverity));
    BulkChange bulkChange = adminIssueClient().bulkChange(query);
    assertThat(bulkChange.totalIssuesChanged()).isEqualTo(nbIssues);

    // Re apply the same bulk change ->  no issue should be changed
    bulkChange = adminIssueClient().bulkChange(query);
    assertThat(bulkChange.totalIssuesChanged()).isEqualTo(0);
    assertThat(bulkChange.totalIssuesNotChanged()).isEqualTo(nbIssues);
  }

  @Test
  public void should_not_apply_bulk_change_if_no_issue_selected() {
    BulkChangeQuery query = (BulkChangeQuery.create().actions("set_severity").actionParameter("set_severity", "severity", "BLOCKER"));
    try {
      adminIssueClient().bulkChange(query);
    } catch (Exception e) {
      verifyHttpException(e, 400);
    }
  }

  @Test
  public void should_not_apply_bulk_change_if_action_is_invalid() {
    analyzeSampleProjectWillSmallNumberOfIssues();
    int nbIssues = 3;
    String[] issueKeys = getIssueKeys(search(IssueQuery.create()).list(), nbIssues);

    BulkChangeQuery query = (BulkChangeQuery.create().issues(issueKeys).actions("invalid"));
    try {
      adminIssueClient().bulkChange(query);
    } catch (Exception e) {
      verifyHttpException(e, 400);
    }
  }

  @Test
  public void should_add_comment_only_on_issues_that_will_be_changed() {
    analyzeSampleProjectWillSmallNumberOfIssues();
    int nbIssues = 3;
    String[] issueKeys = getIssueKeys(search(IssueQuery.create()).list(), nbIssues);

    // Confirm an issue
    adminIssueClient().doTransition(searchRandomIssue().key(), "confirm");

    // Apply a bulk change on unconfirm transition
    BulkChangeQuery query = (BulkChangeQuery.create()
      .issues(issueKeys)
      .actions("do_transition")
      .actionParameter("do_transition", "transition", "unconfirm")
      .comment("this is my comment")
    );
    BulkChange bulkChange = adminIssueClient().bulkChange(query);
    assertThat(bulkChange.totalIssuesChanged()).isEqualTo(1);

    int nbIssuesWithComment = 0;
    for (Issue issue : search(IssueQuery.create().issues(issueKeys)).list()) {
      if (!issue.comments().isEmpty()) {
        nbIssuesWithComment++;
      }
    }
    // Only one issue should have the comment
    assertThat(nbIssuesWithComment).isEqualTo(1);
  }

  @Test
  public void should_apply_bulk_change_with_limited_number_of_issues() {
    analyzeProjectWithALotOfIssues();

    // Check that number of issues is limited from the ws
    String newSeverity = "BLOCKER";
    int nbIssues = 510;
    String[] issueKeys = getIssueKeys(search(IssueQuery.create().pageSize(-1)).list(), nbIssues);

    BulkChange bulkChange = adminIssueClient().bulkChange(
      BulkChangeQuery.create()
        .issues(issueKeys)
        .actions("set_severity")
        .actionParameter("set_severity", "severity", newSeverity)
    );
    assertThat(bulkChange.totalIssuesChanged()).isEqualTo(500);
    assertThat(search(IssueQuery.create().severities(newSeverity)).paging().total()).isEqualTo(500);

    // Check that number of issues is limited from the console bulk change (no change will ne made in this test)
    orchestrator.executeSelenese(Selenese.builder().setHtmlTestsInClasspath("should-bulk-change-be-limited-in-number-of-issues",
      "/selenium/issue/bulk-change/should-bulk-change-be-limited-in-number-of-issues.html",
      // SONAR-4654
      "/selenium/issue/bulk-change/should-bulk-change-be-limited-in-number-of-issues-with-pagination.html"
    ).build());
  }

  /**
   * SONAR-4421
   */
  @Test
  public void should_apply_bulk_change_from_console() {
    analyzeSampleProjectWillSmallNumberOfIssues();

    // Create action plan
    ActionPlan actionPlan = adminActionPlanClient().create(NewActionPlan.create().name("Short term").project("sample").description("Short term issues").deadLine(ItUtils.toDate("2113-01-31")));

    orchestrator.executeSelenese(Selenese.builder().setHtmlTestsInClasspath("should_apply_bulk_change_from_console",
      "/selenium/issue/bulk-change/should-apply-bulk-change.html"
    ).build());

    for (Issue issue : search(IssueQuery.create()).list()) {
      assertThat(issue.status()).isEqualTo("CONFIRMED");
      assertThat(issue.assignee()).isEqualTo("admin");
      assertThat(issue.severity()).isEqualTo("BLOCKER");
      assertThat(issue.actionPlan()).isEqualTo(actionPlan.key());
      assertThat(issue.comments()).hasSize(1);
      assertThat(issue.comments().get(0).htmlText()).isEqualTo("this is my <em>comment</em>");
    }
  }

  @Test
  public void should_apply_bulk_plan_on_issues_from_same_project_from_issues_console() {
    analyzeSampleProjectWillSmallNumberOfIssues();

    // Create action plan
    ActionPlan actionPlan = adminActionPlanClient().create(NewActionPlan.create().name("Short term").project("sample").description("Short term issues").deadLine(ItUtils.toDate("2113-01-31")));

    List<Issue> issues = search(IssueQuery.create()).list();
    assertThat(issues.size()).isGreaterThanOrEqualTo(2);

    // Assign issues to admin in order to link them to a action plan from console without having to select a project
    Issue issue1 = issues.get(0);
    Issue issue2 = issues.get(1);
    adminIssueClient().assign(issue1.key(), "admin");
    adminIssueClient().assign(issue2.key(), "admin");

    orchestrator.executeSelenese(Selenese.builder().setHtmlTestsInClasspath("should_apply_bulk_plan_on_issues_from_same_project_from_console",
      "/selenium/issue/bulk-change/should-apply-bulk-plan-on-issues-from-same-project.html"
    ).build());

    assertThat(searchIssueByKey(issue1.key()).actionPlan()).isEqualTo(actionPlan.key());
    assertThat(searchIssueByKey(issue2.key()).actionPlan()).isEqualTo(actionPlan.key());
  }

  @Test
  public void test_console() {
    analyzeProjectWithALotOfIssues();

    orchestrator.executeSelenese(Selenese.builder().setHtmlTestsInClasspath("test_console",
      "/selenium/issue/bulk-change/should-be-admin-to-apply-bulk-change.html"
    ).build());
  }

  /**
   * SONAR-4418
   */
  @Test
  public void should_apply_bulk_change_from_resource_viewer() {
    analyzeSampleProjectWillSmallNumberOfIssues();

    orchestrator.executeSelenese(Selenese.builder().setHtmlTestsInClasspath("should_apply_bulk_change_from_resource_viewer",
      "/selenium/issue/bulk-change/should-apply-bulk-change-from-resource-viewer.html"
    ).build());
  }

  private void analyzeSampleProjectWillSmallNumberOfIssues() {
    orchestrator.getServer().restoreProfile(FileLocation.ofClasspath("/com/sonar/it/issue/suite/one-issue-per-line-profile.xml"));
    orchestrator.executeBuild(SonarRunner.create(ItUtils.locateProjectDir("shared/xoo-sample"))
      .setProfile("one-issue-per-line"));
  }

  private void analyzeProjectWithALotOfIssues() {
    orchestrator.getServer().restoreProfile(FileLocation.ofClasspath("/com/sonar/it/issue/suite/one-issue-per-line-profile.xml"));
    orchestrator.executeBuild(SonarRunner.create(ItUtils.locateProjectDir("issue/file-with-thousands-issues"))
      .setProfile("one-issue-per-line"));
  }

  private String[] getIssueKeys(List<Issue> issues, int nbIssues) {
    Iterable<Issue> subIssues = Iterables.limit(issues, nbIssues);
    return (newArrayList(Iterables.transform(subIssues, new Function<Issue, String>() {
      public String apply(Issue issue) {
        return issue.key();
      }
    }))).toArray(new String[]{});
  }
}
