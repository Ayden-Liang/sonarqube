import org.sonar.api.SonarPlugin;

import java.util.Arrays;
import java.util.List;

public class SettingsPlugin extends SonarPlugin {
  public List getExtensions() {
    return Arrays.asList(ServerExtensionWithProperties.class, PropertyTypes.class);
  }
}
