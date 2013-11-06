/*
 * Copyright (C) 2013 SonarSource SA
 * All rights reserved
 * mailto:contact AT sonarsource DOT com
 */
package com.sonar.performance.automated;

import org.junit.Rule;
import org.junit.rules.TestName;

import static org.fest.assertions.Assertions.assertThat;

public abstract class PerfTestCase {
  private static final double ACCEPTED_DURATION_VARIATION_IN_PERCENTS = 8.0;

  @Rule
  public TestName testName = new TestName();

  void assertDuration(long duration, long expectedDuration) {
    double variation = 100.0 * (0.0 + duration - expectedDuration) / expectedDuration;
    assertThat(Math.abs(variation)).as(String.format("Expected %d ms, got %d ms", expectedDuration, duration)).isLessThan(ACCEPTED_DURATION_VARIATION_IN_PERCENTS);
    System.out.printf("Test %s executed in %d ms (%.2f %% from target)\n", testName.getMethodName(), duration, variation);
  }
}
