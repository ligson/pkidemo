package common;

//import static sys.*;

//import java.io.Console;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.channels.Channel;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;

public class TopSystem {
	public static System sys;

	public static void arraycopy(Object src, int srcPos, Object dest,
			int destPos, int length) {
		sys.arraycopy(src, srcPos, dest, destPos, length);
	}

	public static String clearProperty(String key) {
		try {
			Method m_clearProperty = sys.getClass().getMethod("clearProperty",
					new Class[] { String.class });
			return (String) m_clearProperty.invoke(String.class,
					new String[] { key });
		} catch (Exception e) {
			e.printStackTrace();
		}
		if (checkVersion("1.4")) {
			String pValue = sys.getProperty(key);
			if (pValue != null) {
				sys.setProperty(key, "");
				return (String) sys.getProperties().remove(key);
			} else {
				return null;
			}
		}
		throw new Error("clearProperty no longer supported.");
	}

	// public static Console console() {
	// return sys.console();
	// }

	public static long currentTimeMillis() {
		return sys.currentTimeMillis();
	}

	public static void exit(int status) {
		sys.exit(status);
	}

	public static void gc() {
		sys.gc();
	}

	public static Map getenv() {
		try {
			Method m_clearProperty = sys.getClass().getMethod("getenv", null);
			return (Map) m_clearProperty.invoke(
					Class.forName("java.lang.ProcessEnvironment"), null);
		} catch (Exception e) {
			e.printStackTrace();
		}
		if (checkVersion("1.4")) {
			Properties ps = sys.getProperties();
			Iterator it = ps.entrySet().iterator();
			Map map = null;
			while (it.hasNext()) {
				Entry en = (Entry) it.next();
				String key = (String) en.getKey();
				String value = (String) en.getValue();
				if (key.startsWith("-D")) {
					if (map == null) {
						map = new HashMap();
					}
					map.put(key.substring(2), value);
				}
			}
			return map;
		}
		throw new Error("getenv no longer supported.");
	}

	public static String getenv(String name) {
		if (checkVersion("1.4")) {
			return sys.getProperty("-D" + name);
		}
		return sys.getenv(name);
	}

	public static Properties getProperties() {
		return sys.getProperties();
	}

	public static String getProperty(String key) {
		return sys.getProperty(key);
	}

	public static String getProperty(String key, String defaultValue) {
		return sys.getProperty(key, defaultValue);
	}

	public static SecurityManager getSecurityManager() {
		return sys.getSecurityManager();
	}

	public static int identityHashCode(Object x) {
		return sys.identityHashCode(x);
	}

	public static Object console() {
		try {
			Method m_clearProperty = sys.getClass().getMethod("console", null);
			return (Map) m_clearProperty.invoke(
					Class.forName("java.io.Console"), null);
		} catch (Exception e) {
			e.printStackTrace();
		}
		throw new Error("getenv no longer supported.");
	}
	
	public static Channel inheritedChannel() throws IOException {
		try {
			Method m_clearProperty = sys.getClass().getMethod(
					"inheritedChannel", null);
			return (Channel) m_clearProperty.invoke(Channel.class, null);
		} catch (Exception e) {
			e.printStackTrace();
		}
		throw new Error("inheritedChannel no longer supported.");
	}

	public static String mapLibraryName(String libname) {
		return sys.mapLibraryName(libname);
	}

	public static long nanoTime() {
		try {
			Method m_clearProperty = sys.getClass().getMethod(
					"nanoTime", null);
			return ((Long) m_clearProperty.invoke(Long.class, null)).longValue();
		} catch (SecurityException e) {
			e.printStackTrace();
		} catch (NoSuchMethodException e) {
			e.printStackTrace();
		} catch (IllegalArgumentException e) {
			e.printStackTrace();
		} catch (IllegalAccessException e) {
			e.printStackTrace();
		} catch (InvocationTargetException e) {
			e.printStackTrace();
		}
		throw new Error("nanoTime no longer supported.");
	}

	public static String setProperty(String key, String value) {
		return sys.setProperty(key, value);
	}

	public static void load(String filename) {
		sys.load(filename);
	}

	public static void loadLibrary(String libname) {
		sys.loadLibrary(libname);
	}

	public static Object a() {
		return null;
	}

	public static void setIn(InputStream in) {
		sys.setIn(in);
	}

	public final static InputStream in = sys.in;
	public final static PrintStream out = sys.out;
	public final static PrintStream err = sys.err;

	/**
	 * JAVA运行/工作路径 The current working directory when the properties were
	 * initialized
	 */
	public static final String WORK_DIR = getProperty("user.dir");
	/**
	 * 运行环境字符编码名称 The character encoding for the default locale
	 */
	public static final String FILE_ENCODING = getProperty("file.encoding");
	/**
	 * 用户名 The username of the current user
	 */
	public static final String USER_NAME = getProperty("user.name");
	/**
	 * 用户本地路径 The home directory of the current user
	 */
	public static final String USER_HOME = getProperty("user.home");
	/**
	 * 用户系统国家(中国CN) The two-letter country code of the default locale
	 */
	public static final String USER_COUNTRY = getProperty("user.country");
	/**
	 * 用户系统语言(中文zh) The two-letter language code of the default locale
	 */
	public static final String USER_LANGUAGE = getProperty("user.language");
	/**
	 * 系统文件夹分隔符 The platform-dependent file separator (e.g., "/" on UNIX, "\"
	 * for Windows)
	 */
	public static final String FILE_SPARATOR = getProperty("file.separator");
	/**
	 * 系统换行符 The platform-dependent line separator (e.g., "\n" on UNIX, "\r\n"
	 * for Windows
	 */
	public static final String LINE_SPARATOR = getProperty("line.separator");
	/**
	 * 系统环境变量分隔符 The platform-dependent path separator (e.g., ":" on UNIX, ","
	 * for Windows)
	 */
	public static final String PATH_SPARATOR = getProperty("path.separator");
	/**
	 * JAVA供应商 A vendor-specific string
	 */
	public static final String JAVA_VENDOR = getProperty("java.vendor");
	/**
	 * JAVA虚拟机供应商 A vendor-specific string
	 */
	public static final String JVM_VENDOR = getProperty("java.vm.vendor");
	/**
	 * JAVA标准版本 The version of the Java specification
	 */
	public static final String JAVA_specification_VERSION = getProperty("java.specification.version");
	/**
	 * JAVA版本 The version of the Java interpreter
	 */
	public static final String JAVA_VERSION = getProperty("java.version");
	/**
	 * 操作系统名称 The name of the operating system
	 */
	public static final String OS_NAME = getProperty("os.name");
	/**
	 * 系统架构(x86) The system architecture
	 */
	public static final String OS_ARCH = getProperty("os.arch");
	/**
	 * 操作系统版本 The operating system version
	 */
	public static final String OS_VERSION = getProperty("os.version");
	/**
	 * JAVA运行库路径 JAVA Library path
	 */
	public static final String JAVA_LIBRARY_PATH = getProperty("java.library.path");
	/**
	 * 运行环境临时路径 The directory in which java should create temporary files
	 */
	public static final String TEMP_PATH = getProperty("java.io.tmpdir");
	/**
	 * JAVA_HOME环境变量的值 The value of the JAVA_HOME environment variable
	 */
	public static final String JAVA_HOME = getProperty("java.home");
	/**
	 * CLASSPATH环境变量的值 The value of the CLASSPATH environment variable
	 */
	public static final String CLASSPATH = getProperty("java.class.path");
	/**
	 * JAVA API版本 The version of the Java API
	 */
	public static final String JAVA_API_VERSION = getProperty("java.class.version");

	public static final boolean checkVersion(String version) {
		return JAVA_VERSION.replaceAll("[\\.|_|0]", "").startsWith(
				version.replaceAll("[\\.|_|0]", ""));
	}
}
