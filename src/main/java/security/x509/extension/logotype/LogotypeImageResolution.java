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

public class LogotypeImageResolution extends ASN1Encodable implements ASN1Choice {
	// LogotypeImageResolution ::= CHOICE {
	// numBits [1] INTEGER, -- Resolution in bits
	// tableSize [2] INTEGER } -- Number of colors or grey tones

	static public final int numBits = 1;
	static public final int tableSize = 2;

	DERInteger obj;
	int tag;

	public static LogotypeImageResolution getInstance(Object obj) {
		if (obj == null || obj instanceof LogotypeImageResolution) { return (LogotypeImageResolution) obj; }

		if (obj instanceof ASN1TaggedObject) {
			ASN1TaggedObject tagObj = (ASN1TaggedObject) obj;
			int tag = tagObj.getTagNo();

			switch (tag) {
			case LogotypeImageResolution.numBits:
				return new LogotypeImageResolution(tagObj.getObject(), tag);
			case LogotypeImageResolution.tableSize:
				return new LogotypeImageResolution(tagObj.getObject(), tag);
			default:
				throw new IllegalArgumentException("unknown tag in factory: " + tag);
			}
		}

		throw new IllegalArgumentException("unknown object in factory");
	}

	public LogotypeImageResolution(DERObject obj, int tag) {
		if ((tag == LogotypeImageResolution.numBits) || (tag == LogotypeImageResolution.tableSize)) {
			this.obj = (DERInteger) obj;
			this.tag = tag;
		} else {
			throw new IllegalArgumentException("tag must be 0 or 1");
		}
	}

	public DERObject toASN1Object() {
		return new DERTaggedObject(false, tag, obj);
	}

}
