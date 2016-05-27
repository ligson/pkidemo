package x509.demo;

import org.apache.commons.codec.binary.Hex;

import java.io.ByteArrayInputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Arrays;

/**
 * Created by ligson on 2016/5/27.
 * 十六进制字符串与x509证书转换
 */
public class HexToX509 {
    public static String x509 = "3082013c3081e4a003020102020a47901280001155957352300a06082a8648ce3d0403023017311530130603550403130c476e756262792050696c6f74301e170d3132303831343138323933325a170d3133303831343138323933325a3031312f302d0603550403132650696c6f74476e756262792d302e342e312d34373930313238303030313135353935373335323059301306072a8648ce3d020106082a8648ce3d030107034200048d617e65c9508e64bcc5673ac82a6799da3c1446682c258c463fffdf58dfd2fa3e6c378b53d795c4a4dffb4199edd7862f23abaf0203b4b8911ba0569994e101300a06082a8648ce3d0403020347003044022060cdb6061e9c22262d1aac1d96d8c70829b2366531dda268832cb836bcd30dfa0220631b1459f09e6330055722c8d89b7f48883b9089b88d60d1d9795902b30410df";

    public static void main(String[] args)  throws  Exception{
        byte[] buffer = Hex.decodeHex(x509.toCharArray());
        System.out.println(Arrays.toString(buffer));
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X509");
        System.out.println(certificateFactory.getProvider().getClass().getName());
        Certificate cert = certificateFactory.generateCertificate(new ByteArrayInputStream(buffer));
        System.out.println(cert);
    }
}
