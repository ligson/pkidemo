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

public class LogotypeImageInfo extends ASN1Encodable {
	// LogotypeImageInfo ::= SEQUENCE {
	// type [0] LogotypeImageType DEFAULT color,
	// fileSize INTEGER, -- In octets
	// xSize INTEGER, -- Horizontal size in pixels
	// ySize INTEGER, -- Vertical size in pixels
	// resolution LogotypeImageResolution OPTIONAL,
	// language [4] IA5String OPTIONAL } -- RFC 3066 Language Tag

	static public final DERInteger grayScale = new DERInteger(0);
	static public final DERInteger color = new DERInteger(1);
	DERInteger type = color;
	DERInteger fileSize = null;
	DERInteger xSize = null;
	DERInteger ySize = null;
	LogotypeImageResolution resolution = null;
	DERIA5String language = null;

	public static LogotypeImageInfo getInstance(Object obj) {
		if (obj == null || obj instanceof LogotypeImageInfo) { return (LogotypeImageInfo) obj; }

		if (obj instanceof ASN1Sequence) {
			ASN1Sequence seq = (ASN1Sequence) obj;
			if (seq.size() >= 4) {
				DERInteger type = (DERInteger) seq.getObjectAt(0);
				DERInteger fileSize = (DERInteger) seq.getObjectAt(1);
				DERInteger xSize = (DERInteger) seq.getObjectAt(2);
				DERInteger ySize = (DERInteger) seq.getObjectAt(3);
				return new LogotypeImageInfo(type.getValue().intValue(), fileSize.getValue().intValue(), xSize.getValue().intValue(), ySize.getValue().intValue());
			}
		}

		throw new IllegalArgumentException("unknown object in factory");
	}

	public LogotypeImageInfo(int type, int fileSizeInOctets, int xSize, // horizontal
																		// size
																		// in
																		// pixels
			int ySize // vertical size in pixels
	) {
		this.type = new DERInteger(type);
		this.fileSize = new DERInteger(fileSizeInOctets);
		this.xSize = new DERInteger(xSize);
		this.ySize = new DERInteger(ySize);
	}

	public DERObject toASN1Object() {
		ASN1EncodableVector v = new ASN1EncodableVector();
		DERTaggedObject t = new DERTaggedObject(0, type);
		v.add(t);
		v.add(fileSize);
		v.add(xSize);
		v.add(ySize);
		if (resolution != null) {
			v.add(resolution);
		}
		if (language != null) {
			v.add(language);
		}
		return new DERSequence(v);
	}

}
