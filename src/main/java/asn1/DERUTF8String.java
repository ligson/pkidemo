package asn1;

import java.io.UnsupportedEncodingException;

public class DERUTF8String {
	private String string;
	
	public DERUTF8String(String string){
		this.string = string;
	}
	
	public DERUTF8String(byte[] utf8String) throws UnsupportedEncodingException{
		this.string = new String(utf8String,"UTF-8");
	}
	
	public String getString(){
		return this.string;
	}
	
	public String toString(){
		return this.string;
	}
}
