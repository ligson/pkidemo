package x509.demo;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.X509Name;

import java.util.Arrays;

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

    public static void main(String[] args) throws Exception {
        X509Name x509Name = new X509Name("o=org,ou=unit,cn=name");
        System.out.println(x509Name);
        X500Name x500Name = X500Name.getInstance(x509Name.getEncoded());
        System.out.println(x500Name);
        System.out.println(Arrays.equals(x500Name.getEncoded(), x509Name.getEncoded()));
        X500Name x500Name1 = gen("org", "unit", "cn");
        System.out.println(x500Name1);
        System.out.println(Arrays.equals(x500Name.getEncoded(), x500Name1.getEncoded()));
    }
}
