package security.pkix;

import java.util.Vector;

import asn1.DERUTF8String;



public class PKIFreeText {
	private Vector<DERUTF8String> v = new Vector<DERUTF8String>();
	
	public PKIFreeText(){
	}
	
	public PKIFreeText(String[] strs){
		for (int i = 0; i < strs.length; i++) {
            v.add(new DERUTF8String(strs[i]));
        }
	}
	
	/**
     * Return the number of string elements present.
     * 
     * @return number of elements present.
     */
    public int size()
    {
        return v.size();
    }
    
    /**
     * Return the String at index i.
     * 
     * @param i index of the string of interest
     * @return the string at index i.
     */
    public DERUTF8String getStringAt(
        int i)
    {
    	return v.get(i);
    }
    
}
