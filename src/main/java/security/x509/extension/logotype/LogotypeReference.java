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

public class LogotypeReference extends ASN1Encodable {
	// LogotypeReference ::= SEQUENCE {
	// refStructHash SEQUENCE SIZE (1..MAX) OF HashAlgAndValue,
	// refStructURI SEQUENCE SIZE (1..MAX) OF IA5String }
	ASN1Sequence refStructHash = null;

	ASN1Sequence refStructURI = null;

	// public static LogotypeReference getInstance(ASN1TaggedObject obj,
	// boolean explicit) {
	// return getInstance(ASN1Sequence.getInstance(obj, explicit));
	// }
	//
	// public static LogotypeReference getInstance(Object obj) {
	// if (obj instanceof LogotypeReference) {
	// return (LogotypeReference) obj;
	// } else if (obj instanceof ASN1Sequence) {
	// return new LogotypeReference((ASN1Sequence) obj);
	// }
	//
	// throw new IllegalArgumentException("unknown object in factory");
	// }

	public static LogotypeReference getInstance(ASN1Sequence seq) {
		ASN1Sequence refStructHashSeq = null;
		ASN1Sequence refStructURISeq = null;
		if (seq.size() != 2) { throw new IllegalArgumentException("size of sequence must be 2 not " + seq.size()); }
		refStructHashSeq = ASN1Sequence.getInstance(seq.getObjectAt(0));
		refStructURISeq = ASN1Sequence.getInstance(seq.getObjectAt(1));
		DigestInfo[] refStructHash = null;
		DERIA5String[] refStructURI = null;
		{
			Vector<DigestInfo> v = new Vector<DigestInfo>();
			for (int i = 0; i < refStructHashSeq.size(); i++) {
				DigestInfo di = DigestInfo.getInstance(refStructHashSeq.getObjectAt(i));
				v.add(di);
			}
			refStructHash = v.toArray(new DigestInfo[refStructHashSeq.size()]);
		}
		{
			Vector<DERIA5String> v = new Vector<DERIA5String>();
			for (int i = 0; i < refStructURISeq.size(); i++) {
				DERIA5String di = DERIA5String.getInstance(refStructURISeq.getObjectAt(i));
				v.add(di);
			}
			refStructHash = v.toArray(new DigestInfo[refStructURISeq.size()]);
		}
		return new LogotypeReference(refStructHash, refStructURI);
	}

	public ASN1Sequence getRefStructHash() {
		return refStructHash;
	}

	public ASN1Sequence getRefStructURI() {
		return refStructURI;
	}

	public LogotypeReference(DigestInfo[] refStructHash, DERIA5String[] refStructURI) {
		if (refStructHash.length == refStructURI.length) {
			this.refStructHash = new DERSequence(refStructHash);
			this.refStructURI = new DERSequence(refStructURI);
		} else {
			throw new IllegalArgumentException("LogotypeReference: The sequences refStructHash and refStructURI must have the same size.");
		}
	}

	public DERObject toASN1Object() {
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(refStructHash);
		v.add(refStructURI);
		return new DERSequence(v);
	}
}
