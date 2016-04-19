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

public class LogotypeInfo extends ASN1Encodable implements ASN1Choice {
	// LogotypeInfo ::= CHOICE {
	// direct [0] LogotypeData,
	// indirect [1] LogotypeReference }

	public static final int direct = 0;
	public static final int indirect = 1;
	ASN1Sequence obj;
	int tag;

	// public static LogotypeInfo getInstance(ASN1TaggedObject tagObj,
	// boolean explicit) {
	// return LogotypeInfo.getInstance(tagObj);
	// }
	// public static LogotypeInfo getInstance(ASN1TaggedObject tagObj,
	// boolean explicit) {
	// return LogotypeInfo.getInstance(ASN1TaggedObject.getInstance(tagObj,
	// true));
	// }

	public static LogotypeInfo getInstance(ASN1TaggedObject tagObj) {
		int tag = tagObj.getTagNo();
		DERObject object = tagObj.getObject();
		if (object instanceof ASN1Sequence) {
			ASN1Sequence seq = (ASN1Sequence) object;
			switch (tag) {
			case LogotypeInfo.direct:
			case LogotypeInfo.indirect:
				return new LogotypeInfo(seq, tag);
			default:
				throw new IllegalArgumentException("unknown tag in factory: " + tag);
			}
		} else {
			throw new IllegalArgumentException("object must be an ASN1Sequence. Not: " + object.getClass().getName());
		}
	}

	public LogotypeInfo(ASN1Sequence obj, int tag) {
		if ((tag == LogotypeInfo.direct) || (tag == LogotypeInfo.indirect)) {
			this.obj = obj;
			this.tag = tag;
		} else {
			throw new IllegalArgumentException("tag must be 0 or 1");
		}
	}

	public LogotypeInfo(LogotypeData direct) {
		this.obj = ASN1Sequence.getInstance(direct.toASN1Object());
		tag = LogotypeInfo.direct;
	}

	public LogotypeInfo(LogotypeReference indirect) {
		this.obj = ASN1Sequence.getInstance(indirect.toASN1Object());
		tag = LogotypeInfo.indirect;
	}

	public LogotypeData getLogotypeData() {
		if (tag == LogotypeInfo.direct) {
			return LogotypeData.getInstance(obj);
		} else {
			return null;
		}
	}

	public LogotypeReference getLogotypeReference() {
		if (tag == LogotypeInfo.indirect) {
			return LogotypeReference.getInstance(obj);
		} else {
			return null;
		}
	}

	public int getTagNo() {
		return tag;
	}

	// public DEREncodable getInfo() {
	// return obj;
	// }

	public DERObject toASN1Object() {
		return new DERTaggedObject(true, tag, obj);
	}
}
