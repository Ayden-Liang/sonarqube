package org.sonar.samples;

import org.sonar.api.SonarPlugin;

import java.util.Arrays;
import java.util.List;

public final class MissingRuleDescriptionPlugin extends SonarPlugin {
  public List getExtensions() {
    return Arrays.asList(MissingRuleDescriptionRepository.class);
  }
}
