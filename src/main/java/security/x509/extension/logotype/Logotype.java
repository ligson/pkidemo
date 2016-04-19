/*
 * Copyright (c) 2006, Axel Nennker - http://axel.nennker.de/ All rights
 * reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * * Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer. * Redistributions in binary
 * form must reproduce the above copyright notice, this list of conditions and
 * the following disclaimer in the documentation and/or other materials provided
 * with the distribution. * The names of the contributors may NOT be used to
 * endorse or promote products derived from this software without specific prior
 * written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE REGENTS AND CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package security.x509.extension.logotype;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.x509.extension.X509ExtensionUtil;

public class Logotype extends ASN1Encodable {
	// LogotypeExtn ::= SEQUENCE {
	// communityLogos [0] EXPLICIT SEQUENCE OF LogotypeInfo OPTIONAL,
	// issuerLogo [1] EXPLICIT LogotypeInfo OPTIONAL,
	// subjectLogo [2] EXPLICIT LogotypeInfo OPTIONAL,
	// otherLogos [3] EXPLICIT SEQUENCE OF OtherLogotypeInfo OPTIONAL }

	public static final DERObjectIdentifier id_pe_logotype = new DERObjectIdentifier("1.3.6.1.5.5.7.1.12");

	public static final DERObjectIdentifier id_logo = new DERObjectIdentifier("1.3.6.1.5.5.7.20");

	public static final DERObjectIdentifier id_logo_loyalty = new DERObjectIdentifier("1.3.6.1.5.5.7.20.1");

	public static final DERObjectIdentifier id_logo_background = new DERObjectIdentifier("1.3.6.1.5.5.7.20.2");

	ASN1Sequence communityLogos = null;

	ASN1TaggedObject issuerLogo = null;

	ASN1TaggedObject subjectLogo = null;

	ASN1Sequence otherLogos = null;

	// public static Logotype getInstance(ASN1TaggedObject obj, boolean
	// explicit) {
	// return getInstance(ASN1Sequence.getInstance(obj, explicit));
	// }
	//
	// public static Logotype getInstance(Object obj) {
	// if (obj instanceof Logotype) {
	// return (Logotype) obj;
	// } else if (obj instanceof ASN1Sequence) {
	// return new Logotype((ASN1Sequence) obj);
	// }
	//
	// throw new IllegalArgumentException("unknown object in factory");
	// }

	public static Logotype getInstance(ASN1Sequence seq) {
		ASN1Sequence communityLogosSeq = null;
		ASN1TaggedObject issuerLogoSeq = null;
		ASN1TaggedObject subjectLogoSeq = null;
		ASN1Sequence otherLogosSeq = null;
		Enumeration e = seq.getObjects();

		while (e.hasMoreElements()) {
			DERTaggedObject o = (DERTaggedObject) e.nextElement();
			DERObject obj = o.getObject();
			switch (o.getTagNo()) {
			case 0:
				communityLogosSeq = ASN1Sequence.getInstance(obj);
				break;
			case 1:
				issuerLogoSeq = (ASN1TaggedObject) obj;
				break;
			case 2:
				subjectLogoSeq = (ASN1TaggedObject) obj;
				break;
			case 3:
				otherLogosSeq = ASN1Sequence.getInstance(obj);
				break;
			default:
				throw new IllegalArgumentException("illegal tag");
			}
		}
		LogotypeInfo[] communityLogos = null;
		if (communityLogosSeq != null) {
			Vector<LogotypeInfo> v = new Vector<LogotypeInfo>();
			for (int index = 0; index < communityLogosSeq.size(); index++) {
				DEREncodable obj = communityLogosSeq.getObjectAt(index);
				ASN1TaggedObject coli = (ASN1TaggedObject) obj;
				LogotypeInfo li = LogotypeInfo.getInstance(coli);
				v.add(li);
			}
			communityLogos = v.toArray(new LogotypeInfo[communityLogosSeq.size()]);
		}
		LogotypeInfo issuerLogo = null;
		if (issuerLogoSeq != null) {
			issuerLogo = LogotypeInfo.getInstance(issuerLogoSeq);
		}
		LogotypeInfo subjectLogo = null;
		if (subjectLogoSeq != null) {
			subjectLogo = LogotypeInfo.getInstance(subjectLogoSeq);
		}
		OtherLogotypeInfo[] otherLogos = null;
		if (otherLogosSeq != null) {
			Vector<OtherLogotypeInfo> v = new Vector<OtherLogotypeInfo>();
			for (int index = 0; index < otherLogosSeq.size(); index++) {
				DEREncodable obj = otherLogosSeq.getObjectAt(index);
				ASN1Sequence coli = (ASN1Sequence) obj;
				OtherLogotypeInfo li = OtherLogotypeInfo.getInstance(coli);
				v.add(li);
			}
			communityLogos = v.toArray(new LogotypeInfo[otherLogosSeq.size()]);
		}
		return new Logotype(communityLogos, issuerLogo, subjectLogo, otherLogos);
	}

	public static Logotype getInstance(byte[] logotypeBytes) throws IOException {
		ByteArrayInputStream stream = new ByteArrayInputStream(logotypeBytes);
		ASN1InputStream aStream = new ASN1InputStream(stream);

		ASN1Sequence root = (ASN1Sequence) aStream.readObject();
		Logotype logotype = Logotype.getInstance(root);
		return logotype;
	}

	public Logotype(LogotypeInfo[] communityLogos, LogotypeInfo issuerLogo, LogotypeInfo subjectLogo, OtherLogotypeInfo[] otherLogos) {
		if (communityLogos != null) {
			this.communityLogos = new DERSequence(communityLogos);
		} else {
			this.communityLogos = null;
		}
		if (issuerLogo != null) {
			this.issuerLogo = (ASN1TaggedObject) issuerLogo.toASN1Object();
		} else {
			this.issuerLogo = null;
		}
		if (subjectLogo != null) {
			this.subjectLogo = (ASN1TaggedObject) subjectLogo.toASN1Object();
		} else {
			this.subjectLogo = null;
		}
		if (otherLogos != null) {
			this.otherLogos = new DERSequence(otherLogos);
		} else {
			this.otherLogos = null;
		}
	}

	public LogotypeInfo[] getCommunityLogos() {
		if (communityLogos != null) {
			Vector<LogotypeDetails> v = new Vector<LogotypeDetails>();
			for (int i = 0; i < communityLogos.size(); i++) {
				v.add(LogotypeDetails.getInstance(communityLogos.getObjectAt(i)));
			}
			LogotypeInfo[] infos = (LogotypeInfo[]) v.toArray(new LogotypeInfo[communityLogos.size()]);
			return infos;
		} else {
			return null;
		}
	}

	public LogotypeInfo getIssuerLogo() {
		if (issuerLogo != null) {
			return LogotypeInfo.getInstance(issuerLogo);
		} else {
			return null;
		}
	}

	public String getIssuerLogoURL(String der) throws IOException, CertificateException {
		String url = null;
		X509Certificate relyingPartyCert = der2cert(der);
		byte[] fromExtensionValue = relyingPartyCert.getExtensionValue(Logotype.id_pe_logotype.getId());
		if ((fromExtensionValue == null) || (fromExtensionValue.length == 0)) {
			// certificat does not contain a logotype extension
			return null;
		}
		ASN1Encodable extVal = X509ExtensionUtil.fromExtensionValue(fromExtensionValue);
		Logotype logotype = Logotype.getInstance((ASN1Sequence) extVal);
		LogotypeInfo logotypeInfo = logotype.getIssuerLogo();
		if (logotypeInfo == null) {
			// logotype contains no issuer logo
			return null;
		}
		if (logotypeInfo.getTagNo() == LogotypeInfo.direct) {
			LogotypeData direct = logotypeInfo.getLogotypeData();
			LogotypeDetails[] images = direct.getImages();
			LogotypeDetails logotypeDetails = images[0];
			// String mediaType = logotypeDetails.getMediaType();
			// assertEquals("image/gif", mediaType);
			// DigestInfo[] dis = logotypeDetails.getLogotypeHash();
			// assertEquals(1, dis.length);
			// DigestInfo di = dis[0];
			// AlgorithmIdentifier algId = di.getAlgorithmId();
			// assertEquals("1.3.14.3.2.26", algId.getObjectId().getId());
			// byte[] digest = di.getDigest();
			// byte[] expected = { -113, -27, -45, 26, -122, -84, -115,
			// -114, 107, -61, -49, -128, 106, -44, 72, 24, 44, 123, 25,
			// 46};
			// assertEquals(expected.length , digest.length);
			// for (int i=0; i<digest.length; i++) {
			// assertEquals(expected[i], digest[i]);
			// }
			String[] uris = logotypeDetails.getLogotypeURI();
			// assertEquals(1, uris.length);
			url = uris[0];
			// assertEquals("http://logo.verisign.com/vslogo.gif", uri);
		} else if (logotypeInfo.getTagNo() == LogotypeInfo.indirect) {
			// LogotypeReference indirect = logotypeInfo
			// .getLogotypeReference();
			// TODO
			// LogotypeReference indirect =
			// LogotypeReference.getInstance((ASN1TaggedObject)issuerLogo.
			// toASN1Object(),
			// false);
			// assertNotNull(indirect);
		}
		return url;
	}

	public LogotypeInfo getSubjectLogo() {
		if (subjectLogo != null) {
			return LogotypeInfo.getInstance(subjectLogo);
		} else {
			return null;
		}
	}

	public LogotypeInfo[] getOtherLogos() {
		if (otherLogos != null) {
			Vector<LogotypeDetails> v = new Vector<LogotypeDetails>();
			for (int i = 0; i < otherLogos.size(); i++) {
				v.add(LogotypeDetails.getInstance(otherLogos.getObjectAt(i)));
			}
			LogotypeInfo[] infos = (LogotypeInfo[]) v.toArray(new LogotypeInfo[otherLogos.size()]);
			return infos;
		} else {
			return null;
		}
	}

	/**
	 * Produce an object suitable for an ASN1OutputStream.
	 */
	public DERObject toASN1Object() {
		ASN1EncodableVector v = new ASN1EncodableVector();

		if (communityLogos != null) {
			v.add(new DERTaggedObject(true, 0, communityLogos));
		}

		if (issuerLogo != null) {
			v.add(new DERTaggedObject(true, 1, issuerLogo));
		}

		if (subjectLogo != null) {
			v.add(new DERTaggedObject(true, 2, subjectLogo));
		}

		if (otherLogos != null) {
			v.add(new DERTaggedObject(true, 3, otherLogos));
		}

		return new DERSequence(v);
	}

	public static X509Certificate der2cert(String der) throws CertificateException {
		byte[] certBytes = Base64.decode(der);
		ByteArrayInputStream is = new ByteArrayInputStream(certBytes);
		BufferedInputStream bis = new BufferedInputStream(is);
		CertificateFactory cf = null;
		X509Certificate cert = null;
		cf = CertificateFactory.getInstance("X.509");
		cert = (X509Certificate) cf.generateCertificate(bis);
		return cert;
	}
}
