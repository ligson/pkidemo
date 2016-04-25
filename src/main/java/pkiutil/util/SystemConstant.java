package pkiutil.util;
/**
 * java系统环境参数
 * @author wang_xuanmin
 *
 */
public interface SystemConstant {
	/**
	 * JAVA运行/工作路径 The current working directory when the properties were
	 * initialized
	 */
	public static final String WORK_DIR = System.getProperty("user.dir");
	/**
	 * 运行环境编码格式 The character encoding for the default locale
	 */
	public static final String FILE_ENCODING = System.getProperty("file.encoding");
	/**
	 * 用户名 The username of the current user
	 */
	public static final String USER_NAME = System.getProperty("user.name");
	/**
	 * 用户本地路径 The home directory of the current user
	 */
	public static final String USER_HOME = System.getProperty("user.home");
	/**
	 * 用户系统国家(中国CN) The two-letter country code of the default locale
	 */
	public static final String USER_COUNTRY = System.getProperty("user.country");
	/**
	 * 用户系统语言(中文zh) The two-letter language code of the default locale
	 */
	public static final String USER_LANGUAGE = System.getProperty("user.language");
	/**
	 * 系统文件夹分隔符 The platform-dependent file separator (e.g., "/" on UNIX, "\"
	 * for Windows)
	 */
	public static final String FILE_SPARATOR = System.getProperty("file.separator");
	/**
	 * 系统换行符 The platform-dependent line separator (e.g., "\n" on UNIX, "\r\n"
	 * for Windows
	 */
	public static final String LINE_SPARATOR = System.getProperty("line.separator");
	/**
	 * 系统环境变量分隔符 The platform-dependent path separator (e.g., ":" on UNIX, ","
	 * for Windows)
	 */
	public static final String PATH_SPARATOR = System.getProperty("path.separator");
	/**
	 * JAVA供应商 A vendor-specific string
	 */
	public static final String JAVA_VENDOR = System.getProperty("java.vendor");
	/**
	 * JAVA虚拟机供应商 A vendor-specific string
	 */
	public static final String JVM_VENDOR = System.getProperty("java.vm.vendor");
	/**
	 * JAVA标准版本 The version of the Java specification
	 */
	public static final String JAVA_specification_VERSION = System.getProperty("java.specification.version");
	/**
	 * JAVA版本 The version of the Java interpreter
	 */
	public static final String JAVA_VERSION = System.getProperty("java.version");
	/**
	 * 操作系统名称 The name of the operating system
	 */
	public static final String OS_NAME = System.getProperty("os.name");
	/**
	 * 系统架构(x86) The system architecture
	 */
	public static final String OS_ARCH = System.getProperty("os.arch");
	/**
	 * 操作系统版本 The operating system version
	 */
	public static final String OS_VERSION = System.getProperty("os.version");
	/**
	 * JAVA运行库路径 JAVA Library path
	 */
	public static final String JAVA_LIBRARY_PATH = System.getProperty("java.library.path");
	/**
	 * 运行环境临时路径 The directory in which java should create temporary files
	 */
	public static final String TEMP_PATH = System.getProperty("java.io.tmpdir");
	/**
	 * JAVA_HOME环境变量的值 The value of the JAVA_HOME environment variable
	 */
	public static final String JAVA_HOME = System.getProperty("java.home");
	/**
	 * CLASSPATH环境变量的值 The value of the CLASSPATH environment variable
	 */
	public static final String CLASSPATH = System.getProperty("java.class.path");
	/**
	 * JAVA API版本 The version of the Java API
	 */
	public static final String JAVA_API_VERSION = System.getProperty("java.class.version");

}
