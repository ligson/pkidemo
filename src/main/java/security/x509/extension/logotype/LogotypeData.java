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

import java.util.Vector;

public class LogotypeData extends ASN1Encodable {
	// LogotypeData ::= SEQUENCE {
	// image SEQUENCE OF LogotypeImage OPTIONAL,
	// audio [1] SEQUENCE OF LogotypeAudio OPTIONAL }

	ASN1Sequence image = null;
	ASN1Sequence audio = null;

	// public static LogotypeData getInstance(ASN1TaggedObject obj, boolean
	// explicit) {
	// return getInstance(ASN1Sequence.getInstance(obj, explicit));
	// }
	//
	// public static LogotypeData getInstance(Object obj) {
	// if (obj instanceof LogotypeData) {
	// return (LogotypeData) obj;
	// } else if (obj instanceof ASN1Sequence) {
	// return new LogotypeData((ASN1Sequence) obj);
	// }
	//
	// throw new IllegalArgumentException("unknown object in factory");
	// }

	public static LogotypeData getInstance(ASN1Sequence sequence) {
		ASN1Sequence image = null;
		ASN1Sequence audio = null;
		if (sequence.size() == 1) {
			Object obj = sequence.getObjectAt(0);
			if (obj instanceof ASN1Sequence) {
				image = ASN1Sequence.getInstance(obj);
			} else if (obj instanceof ASN1TaggedObject) {
				ASN1TaggedObject first = (ASN1TaggedObject) obj;
				if (first.getTagNo() == 1) {
					audio = ASN1Sequence.getInstance(first.getObject());
				}
			} else {
				throw new IllegalArgumentException("unknown object in sequence with length 1: " + obj.getClass().getName());
			}
		} else if (sequence.size() == 2) {
			ASN1TaggedObject first = (ASN1TaggedObject) sequence.getObjectAt(0);
			ASN1TaggedObject second = (ASN1TaggedObject) sequence.getObjectAt(1);
			if (first.getTagNo() == 1) {
				audio = ASN1Sequence.getInstance(first.getObject());
				image = ASN1Sequence.getInstance(second.getObject());
			} else if (second.getTagNo() == 1) {
				audio = ASN1Sequence.getInstance(second.getObject());
				image = ASN1Sequence.getInstance(first.getObject());
			} else {
				throw new IllegalArgumentException("one of the objects in this sequence must be tagged with 1");
			}
		} else {
			throw new IllegalArgumentException("size of sequence must be 2 not " + sequence.size());
		}
		LogotypeDetails[] images = null;
		if (image != null) {
			Vector<LogotypeDetails> v = new Vector<LogotypeDetails>(image.size());
			for (int i = 0; i < image.size(); i++) {
				ASN1Sequence seq = ASN1Sequence.getInstance(image.getObjectAt(i));
				LogotypeDetails logotypeImage = LogotypeDetails.getInstance(seq);
				v.add(logotypeImage);
			}
			images = v.toArray(new LogotypeDetails[image.size()]);
		}
		LogotypeAudio[] audios = null;
		if (audio != null) {
			Vector<LogotypeAudio> v = new Vector<LogotypeAudio>(audio.size());
			for (int i = 0; i < audio.size(); i++) {
				ASN1Sequence seq = ASN1Sequence.getInstance(audio.getObjectAt(i));
				LogotypeAudio logotypeImage = LogotypeAudio.getInstance(seq);
				v.add(logotypeImage);
			}
			audios = v.toArray(new LogotypeAudio[audio.size()]);
		}
		return new LogotypeData(images, audios);
	}

	// public LogotypeData(LogotypeImage[] image, LogotypeAudio[] audio) {
	public LogotypeData(LogotypeDetails[] image, LogotypeAudio[] audio) {
		if (image != null) {
			ASN1EncodableVector v = new ASN1EncodableVector();
			for (int i = 0; i < image.length; i++) {
				v.add(image[i].toASN1Object());
			}
			this.image = new DERSequence(v);
		} else {
			this.image = null;
		}
		if (audio != null) {
			ASN1EncodableVector v = new ASN1EncodableVector();
			for (int i = 0; i < audio.length; i++) {
				v.add(audio[i].toASN1Object());
			}
			this.audio = new DERSequence(v);
		} else {
			this.audio = null;
		}
	}

	@SuppressWarnings("unchecked")
	public LogotypeDetails[] getImages() {
		Vector v = new Vector();
		for (int i = 0; i < image.size(); i++) {
			v.add(LogotypeDetails.getInstance(image.getObjectAt(i)));
		}
		LogotypeDetails[] images = (LogotypeDetails[]) v.toArray(new LogotypeDetails[image.size()]);
		return images;
	}

	/**
	 * Produce an object suitable for an ASN1OutputStream.
	 */
	public DERObject toASN1Object() {
		ASN1EncodableVector v = new ASN1EncodableVector();

		if (image != null) {
			v.add(image);
		}

		if (audio != null) {
			v.add(new DERTaggedObject(true, 1, audio));
		}

		return new DERSequence(v);
	}

}
