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

public class LogotypeImage extends ASN1Encodable {
	// LogotypeImage ::= SEQUENCE {
	// imageDetails LogotypeDetails,
	// imageInfo LogotypeImageInfo OPTIONAL }

	ASN1Sequence imageDetails = null;
	ASN1Sequence imageInfo = null;

	// public static LogotypeImage getInstance(ASN1TaggedObject obj, boolean
	// explicit) {
	// return getInstance(ASN1Sequence.getInstance(obj, explicit));
	// }

	// public static LogotypeImage getInstance(Object obj) {
	// if (obj instanceof LogotypeImage) {
	// return (LogotypeImage) obj;
	// } else if (obj instanceof ASN1Sequence) {
	// return new LogotypeImage((ASN1Sequence) obj);
	// }
	//
	// throw new IllegalArgumentException("unknown object in factory");
	// }

	public static LogotypeImage getInstance(ASN1Sequence sequence) {
		ASN1Sequence imageDetails = null;
		ASN1Sequence imageInfo = null;
		if (sequence.size() == 1) {
			Object obj = sequence.getObjectAt(0);
			if (obj instanceof ASN1Sequence) {
				imageDetails = (DERSequence) obj;
			} else {
				throw new IllegalArgumentException("first object in sequence must be a sequence, not a: " + obj.getClass().getName());
			}
		} else if (sequence.size() == 2) {
			Object obj = sequence.getObjectAt(0);
			if (obj instanceof ASN1Sequence) {
				imageDetails = ASN1Sequence.getInstance(obj);
			} else {
				throw new IllegalArgumentException("first object of two in sequence must be a sequence, not a: " + obj.getClass().getName());
			}
			obj = sequence.getObjectAt(1);
			if (obj instanceof ASN1Sequence) {
				imageInfo = ASN1Sequence.getInstance(obj);
			} else {
				throw new IllegalArgumentException("second object in sequence must be a sequence, not a: " + obj.getClass().getName());
			}
		} else {
			throw new IllegalArgumentException("size of sequence must be 2 not " + sequence.size());
		}
		LogotypeDetails logotypeDetails = LogotypeDetails.getInstance(imageDetails);
		LogotypeImageInfo logotypeImageInfo = null;
		if (imageInfo != null) {
			logotypeImageInfo = LogotypeImageInfo.getInstance(imageInfo);
		}
		return new LogotypeImage(logotypeDetails, logotypeImageInfo);
	}

	public LogotypeImage(LogotypeDetails imageDetails, LogotypeImageInfo imageInfo) {
		this.imageDetails = ASN1Sequence.getInstance(imageDetails.toASN1Object());
		if (imageInfo != null) {
			this.imageInfo = ASN1Sequence.getInstance(imageInfo.toASN1Object());
		}
	}

	/**
	 * Produce an object suitable for an ASN1OutputStream.
	 */
	public DERObject toASN1Object() {
		ASN1EncodableVector v = new ASN1EncodableVector();

		v.add(imageDetails);

		if (imageInfo != null) {
			v.add(imageInfo);
		}

		return new DERSequence(v);
	}
}
