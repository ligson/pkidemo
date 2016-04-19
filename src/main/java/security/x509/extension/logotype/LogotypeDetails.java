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

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.DigestInfo;

import java.util.Vector;

public class LogotypeDetails extends ASN1Encodable {
	DERIA5String mediaType = null;

	ASN1Sequence logotypeHash = null;

	ASN1Sequence logotypeURI = null;

	public static LogotypeDetails getInstance(ASN1TaggedObject obj, boolean explicit) {
		return getInstance(ASN1Sequence.getInstance(obj, explicit));
	}

	public static LogotypeDetails getInstance(Object obj) {
		if (obj instanceof LogotypeDetails) {
			return (LogotypeDetails) obj;
		} else if (obj instanceof ASN1Sequence) { return new LogotypeDetails((ASN1Sequence) obj); }

		throw new IllegalArgumentException("unknown object in factory");
	}

	public LogotypeDetails(ASN1Sequence seq) {
		if (seq.size() != 3) { throw new IllegalArgumentException("size of sequence must be 3 not " + seq.size()); }
		this.mediaType = DERIA5String.getInstance(seq.getObjectAt(0));
		this.logotypeHash = ASN1Sequence.getInstance(seq.getObjectAt(1));
		this.logotypeURI = ASN1Sequence.getInstance(seq.getObjectAt(2));
	}

	public LogotypeDetails(String mediaType, DigestInfo[] logotypeHash, String[] logotypeURI) {
		this.mediaType = new DERIA5String(mediaType);
		this.logotypeHash = new DERSequence(logotypeHash);
		ASN1EncodableVector v = new ASN1EncodableVector();
		for (int i = 0; i < logotypeURI.length; i++) {
			v.add(new DERIA5String(logotypeURI[i]));
		}
		this.logotypeURI = new DERSequence(v);
	}

	public String getMediaType() {
		return mediaType.getString();
	}

	public DigestInfo[] getLogotypeHash() {
		Vector<DigestInfo> v = new Vector<DigestInfo>();
		for (int i = 0; i < logotypeHash.size(); i++) {
			v.add(DigestInfo.getInstance(logotypeHash.getObjectAt(i)));
		}
		DigestInfo[] infos = (DigestInfo[]) v.toArray(new DigestInfo[logotypeHash.size()]);
		return infos;
	}

	public String[] getLogotypeURI() {
		Vector<String> v = new Vector<String>();
		for (int i = 0; i < logotypeURI.size(); i++) {
			v.add(DERIA5String.getInstance(logotypeURI.getObjectAt(i)).getString());
		}
		String[] infos = (String[]) v.toArray(new String[logotypeURI.size()]);
		return infos;
	}

	public DERObject toASN1Object() {
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(mediaType);
		v.add(logotypeHash);
		v.add(logotypeURI);
		return new DERSequence(v);
	}

}
