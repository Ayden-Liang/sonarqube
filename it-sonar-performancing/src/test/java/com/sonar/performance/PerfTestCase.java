/*
 * Copyright (C) 2013-2014 SonarSource SA
 * All rights reserved
 * mailto:contact AT sonarsource DOT com
 */
package com.sonar.performance;

import com.sonar.orchestrator.build.SonarRunner;
import com.sonar.orchestrator.locator.FileLocation;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.junit.Rule;
import org.junit.rules.TestName;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

import static org.fest.assertions.Assertions.assertThat;

public abstract class PerfTestCase {
  private static final double ACCEPTED_DURATION_VARIATION_IN_PERCENTS = 8.0;

  @Rule
  public TestName testName = new TestName();

  protected void assertDurationAround(long duration, long expectedDuration) {
    double variation = 100.0 * (0.0 + duration - expectedDuration) / expectedDuration;
    System.out.printf("Test %s : executed in %d ms (%.2f %% from target)\n", testName.getMethodName(), duration, variation);
    assertThat(Math.abs(variation)).as(String.format("Expected %d ms, got %d ms", expectedDuration, duration)).isLessThan(ACCEPTED_DURATION_VARIATION_IN_PERCENTS);
  }

  protected void assertDurationLessThan(long duration, long maxDuration) {
    System.out.printf("Test %s : %d ms (max allowed is %d)\n", testName.getMethodName(), duration, maxDuration);
    assertThat(duration).as(String.format("Expected less than %d ms, got %d ms", maxDuration, duration)).isLessThanOrEqualTo(maxDuration);
  }

  protected Properties readProfiling(File baseDir, String moduleKey) throws IOException {
    File profilingFile = new File(baseDir, ".sonar/profiling/" + moduleKey + "-profiler.properties");
    Properties props = new Properties();
    FileInputStream in = FileUtils.openInputStream(profilingFile);
    try {
      props.load(in);
    } finally {
      IOUtils.closeQuietly(in);
    }
    return props;
  }

  public static SonarRunner newSonarRunner(String sonarRunnerOpts, String... props) {
    return SonarRunner.create()
      .setProperties(props)
      .setEnvironmentVariable("SONAR_RUNNER_OPTS", sonarRunnerOpts)
      .setRunnerVersion("2.3")
      .setProjectDir(FileLocation.of("projects/xoo-sample").getFile());
  }
}
