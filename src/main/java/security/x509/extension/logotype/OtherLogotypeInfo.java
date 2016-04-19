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

public class OtherLogotypeInfo extends ASN1Encodable {
	DERObjectIdentifier logotypeType = null;
	ASN1TaggedObject logotypeInfo = null;

	public static OtherLogotypeInfo getInstance(ASN1Sequence obj) {
		if (obj.size() == 2) {
			DERObjectIdentifier logotypeType = DERObjectIdentifier.getInstance(obj.getObjectAt(0));
			ASN1TaggedObject logotypeInfo = (ASN1TaggedObject) obj.getObjectAt(1);
			return new OtherLogotypeInfo(logotypeType, logotypeInfo);
		}
		throw new IllegalArgumentException("sequence must have length 2");
	}

	public OtherLogotypeInfo(DERObjectIdentifier logotypeType, ASN1TaggedObject logotypeInfo) {
		this.logotypeType = logotypeType;
		this.logotypeInfo = logotypeInfo;
	}

	public LogotypeInfo getLogotypeInfo() {
		return LogotypeInfo.getInstance(logotypeInfo);
	}

	public DERObject toASN1Object() {
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(logotypeType);
		v.add(logotypeInfo);
		return new DERSequence(v);
	}
}
