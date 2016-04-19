package pkiutil;

import java.lang.reflect.Field;

public class ClassUtil {
	public static Object getProperty(Object owner, String fieldName) throws Exception {
		Class<? extends Object> ownerClass = owner.getClass();
		Field field = ownerClass.getField(fieldName);
		Object property = field.get(owner);
		return property;
	}

	public static Object getStaticProperty(String className, String fieldName) throws Exception {
		Class<?> ownerClass = Class.forName(className);
		Field field = ownerClass.getField(fieldName);
		Object property = field.get(ownerClass);
		return property;
	}

}
