package x509.demo;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Provider;
import java.security.Security;

/**
 * Created by ligson on 2016/4/22.
 */
public class Providers {
    public static Provider provider = new BouncyCastleProvider();

    static {
        Security.addProvider(provider);
    }
}
