package x509.demo;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;

/**
 * Created by ligson on 2016/4/22.
 */
public class X500NameGen {
    public static X500Name gen(String o, String ou, String cn) {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.CN, cn);
        builder.addRDN(BCStyle.OU, ou);
        builder.addRDN(BCStyle.O, o);
        return builder.build();
    }
}
