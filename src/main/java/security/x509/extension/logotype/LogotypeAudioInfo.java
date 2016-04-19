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

import java.math.BigInteger;

public class LogotypeAudioInfo extends ASN1Encodable {
	// LogotypeAudioInfo ::= SEQUENCE {
	// fileSize INTEGER, -- In octets
	// playTime INTEGER, -- In milliseconds
	// channels INTEGER, -- 1=mono, 2=stereo, 4=quad
	// sampleRate [3] INTEGER OPTIONAL, -- Samples per second
	// language [4] IA5String OPTIONAL } -- RFC 3066 Language Tag
	DERInteger fileSize;
	DERInteger playTime;
	DERInteger channels;
	DERInteger sampleRate;
	DERIA5String language;

	// public static LogotypeAudioInfo getInstance(Object obj) {
	// if (obj instanceof LogotypeData) {
	// return (LogotypeAudioInfo) obj;
	// } else if (obj instanceof ASN1Sequence) {
	// return new LogotypeAudioInfo((ASN1Sequence) obj);
	// }
	//
	// throw new IllegalArgumentException("unknown object in factory");
	// }

	public LogotypeAudioInfo(ASN1Sequence sequence) {
		if (sequence.size() >= 3) {
			fileSize = DERInteger.getInstance(sequence.getObjectAt(0));
			playTime = DERInteger.getInstance(sequence.getObjectAt(1));
			channels = DERInteger.getInstance(sequence.getObjectAt(2));
			sampleRate = null;
			language = null;
			if (sequence.size() >= 4) {
				DERTaggedObject four = (DERTaggedObject) sequence.getObjectAt(3);
				if (four.getTagNo() == 3) {
					sampleRate = (DERInteger) four.getObject();
				} else if (four.getTagNo() == 4) {
					language = (DERIA5String) four.getObject();
				} else {
					throw new IllegalArgumentException("unknown tag" + four.getTagNo());
				}
				if (sequence.size() == 5) {
					DERTaggedObject five = (DERTaggedObject) sequence.getObjectAt(4);
					if (five.getTagNo() == 3) {
						sampleRate = (DERInteger) five.getObject();
					} else if (five.getTagNo() == 4) {
						language = (DERIA5String) five.getObject();
					} else {
						throw new IllegalArgumentException("unknown tag" + five.getTagNo());
					}
				} else {
					throw new IllegalArgumentException("more than 5 elements in sequence: " + sequence.size());
				}
			}
		}
		throw new IllegalArgumentException("sequence must have more than 3 elements. not: " + sequence.size());
	}

	public LogotypeAudioInfo(BigInteger fileSize, BigInteger playTime, BigInteger channels, BigInteger sampleRate, String language) {
		fileSize = null;
		playTime = null;
		channels = null;
		sampleRate = null;
		language = null;
	}

	public DERObject toASN1Object() {
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(fileSize);
		v.add(playTime);
		v.add(channels);
		v.add(sampleRate);
		v.add(language);
		if (sampleRate != null) {
			v.add(sampleRate);
		}

		if (language != null) {
			v.add(new DERTaggedObject(true, 1, language));
		}
		return new DERSequence(v);
	}

}
