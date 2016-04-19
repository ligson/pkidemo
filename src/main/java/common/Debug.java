package common;

import java.util.HashMap;
import java.util.Map;

public class Debug {

    private String prefix;
    public static boolean enableAll = false;
    public boolean enable = false;
    private static Map<String, Debug> list;

    public static Debug getInstance(String clazz) {
	if (null == list) {
	    list = new HashMap<String, Debug>();
	}
	Debug debug = list.get(clazz);
	if (null == debug) {
	    debug = new Debug(clazz);
	}
	return debug;
    }

    private Debug(String clazz) {
	this.prefix = clazz;
    }

    public void println(String debugMsg) {
	if (enableAll || enable)
	    System.out.println("[DEBUG]"+this.prefix + ": " + debugMsg);
    }

}
