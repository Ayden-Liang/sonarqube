package sqale;

import com.sonarsource.license.api.LicensedPlugin;
import com.sonarsource.license.api.LicensedPluginMetadata;
import org.sonar.api.Properties;
import org.sonar.api.Property;
import org.sonar.api.PropertyType;

import java.util.Arrays;
import java.util.List;

@Properties(
  @Property(name = "License", key = "sonar.sqale.license.secured", type = PropertyType.LICENSE)
)
public final class FakeSqalePlugin extends LicensedPlugin {

  @Override
  protected List doGetExtensions() {
    return Arrays.asList(BatchPrintBip.class, StoreServerProperty.class);
  }

  @Override
  protected LicensedPluginMetadata doGetPluginMetadata() {
    return LicensedPluginMetadata.create("sqale", "sonar.sqale.license.secured");
  }
}
