package security.x509.extension;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;

import security.x509.extension.logotype.Logotype;
import security.x509.extension.logotype.LogotypeAudio;
import security.x509.extension.logotype.LogotypeData;
import security.x509.extension.logotype.LogotypeDetails;
import security.x509.extension.logotype.LogotypeInfo;
import security.x509.extension.logotype.OtherLogotypeInfo;
import pkiutil.ImageDataURLCodec;


public class LogotypeGenerator {
	private byte[] subjectLogoImageBytes;
	public static final String SHA1 = "SHA-1";
	public static final String SHA1_OID = "1.3.14.3.2.26";
	private String messageDigestAlgorithm = SHA1;
	private String messageDigestAlgorithmIdentifier = SHA1_OID;

	public void updateSubjectLogo(InputStream is, int off, int len) throws IOException {
		subjectLogoImageBytes = new byte[len];
		is.read(subjectLogoImageBytes, off, len);
	}

	public Logotype genLogotype() throws IOException, NoSuchAlgorithmException {
		String mediaType = "image/gif";
		// 将图片编码为imageDataURL
		String imageDataURL = ImageDataURLCodec.encode(subjectLogoImageBytes);
		if (imageDataURL.indexOf(mediaType) < 0) { throw new IOException("Needs gif file."); }
		// 对图片做SHA1消息摘要
		MessageDigest md = MessageDigest.getInstance(messageDigestAlgorithm);
		md.update(subjectLogoImageBytes);
		AlgorithmIdentifier algId = new AlgorithmIdentifier(messageDigestAlgorithmIdentifier);
		byte[] digest = md.digest();
		// 生成logotype扩展项
		DigestInfo digestInfo = new DigestInfo(algId, digest);
		DigestInfo[] logotypeHash = { digestInfo };
		String[] logotypeURI = { imageDataURL };
		LogotypeDetails imageDetails = new LogotypeDetails(mediaType, logotypeHash, logotypeURI);
		// LogotypeImageInfo imageInfo = null;
		// LogotypeImage image = new LogotypeImage(imageDetails, imageInfo);
		// LogotypeImage[] images = { image };
		LogotypeDetails[] images = { imageDetails };
		LogotypeAudio[] audio = null;
		LogotypeData direct = new LogotypeData(images, audio);
		LogotypeInfo[] communityLogos = null;
		LogotypeInfo issuerLogo = new LogotypeInfo(direct);
		LogotypeInfo subjectLogo = null;
		OtherLogotypeInfo[] otherLogos = null;
		Logotype logotype = new Logotype(communityLogos, issuerLogo, subjectLogo, otherLogos);
		return logotype;
		// DERObject obj = logotype.toASN1Object();
		// byte[] logotypeBytes = obj.getDEREncoded();
		// System.out.println(DataUtil.transformByteArrayToHexString(logotypeBytes
		// ));
	}
}
