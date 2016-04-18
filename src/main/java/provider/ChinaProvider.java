package provider;

import java.security.Provider;

/**
 * Created by ligson on 2016/4/18.
 */
public class ChinaProvider extends Provider {
    /**
     * Constructs a provider with the specified name, version number,
     * and information.
     *
     * @param name    the provider name.
     * @param version the provider version number.
     * @param info    a description of the provider and its services.
     */
    protected ChinaProvider(String name, double version, String info) {
        super(name, version, info);
    }

    public ChinaProvider() {
        super("ChinaProvider", 1.0, "自主加密服务提供");
    }

}
