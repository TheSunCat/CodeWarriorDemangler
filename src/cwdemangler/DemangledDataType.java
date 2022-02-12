/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package cwdemangler;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A class to represent a demangled data type.
 */
public class DemangledDataType extends DemangledType {

	private static final Pattern ARRAY_SUBSCRIPT_PATTERN = Pattern.compile("\\[\\d*\\]");

	public static final char SPACE = ' ';

	public static final String UNSIGNED = "unsigned";
	public static final String SIGNED = "signed";

	public static final String ARR_NOTATION = "[]";
	public static final String REF_NOTATION = "&";
	public static final String PTR_NOTATION = "*";

	public static final String VOLATILE = "volatile";
	public static final String COMPLEX = "complex";
	public static final String CLASS = "class";
	public static final String ENUM = "enum";
	public static final String STRUCT = "struct";
	public static final String UNION = "union";
	public static final String CONST = "const";
	public static final String COCLASS = "coclass";
	public static final String COINTERFACE = "cointerface";

	public final static String VARARGS = "...";
	public final static String VOID = "void";
	public final static String BOOL = "bool";
	public final static String CHAR = "char";
	public final static String WCHAR_T = "wchar_t";
	public final static String SHORT = "short";
	public final static String INT = "int";
	public final static String INT0_T = "int0_t";
	public final static String LONG = "long";
	public final static String LONG_LONG = "long long";
	public final static String FLOAT = "float";
	public final static String DOUBLE = "double";
	public final static String INT8 = "__int8";
	public final static String INT16 = "__int16";
	public final static String INT32 = "__int32";
	public final static String INT64 = "__int64";
	public final static String INT128 = "__int128";
	public final static String FLOAT128 = "__float128";
	public final static String LONG_DOUBLE = "long double";
	public final static String PTR64 = "__ptr64";
	public final static String STRING = "string";
	public final static String UNDEFINED = "undefined";
	public static final String UNALIGNED = "__unaligned";
	public static final String RESTRICT = "__restrict";

	public final static String[] PRIMITIVES = { VOID, BOOL, CHAR, WCHAR_T, SHORT, INT, INT0_T, LONG,
		LONG_LONG, FLOAT, DOUBLE, INT128, FLOAT128, LONG_DOUBLE, };

	private int arrayDimensions = 0;
	private boolean isClass;
	private boolean isComplex;
	private boolean isEnum;
	private boolean isPointer64;
	private boolean isReference;
	private boolean isRValueReference;
	private boolean isSigned;
	private boolean isStruct;
	private boolean isTemplate;
	private boolean isUnaligned;
	private boolean isUnion;
	private boolean isUnsigned;
	private boolean isVarArgs;
	private int pointerLevels = 0;
	private String enumType;
	private boolean isRestrict;
	private String basedName;
	private String memberScope;
	private boolean isCoclass;
	private boolean isCointerface;

	public DemangledDataType(String mangled, String originaDemangled, String name) {
		super(mangled, originaDemangled, name);
	}

	public int getPointerLevels() {
		return pointerLevels;
	}

	public void incrementPointerLevels() {
		pointerLevels++;
	}

	public void setArray(int dimensions) {
		this.arrayDimensions = dimensions;
	}

	public int getArrayDimensions() {
		return arrayDimensions;
	}

	public void setClass() {
		isClass = true;
	}

	public void setComplex() {
		isComplex = true;
	}

	public void setEnum() {
		isEnum = true;
	}

	public void setPointer64() {
		isPointer64 = true;
	}

	public void setReference() {
		isReference = true;
	}

	/**
	 * rvalue reference; C++11
	 */
	public void setRValueReference() {
		isRValueReference = true;
	}

	public void setSigned() {
		isSigned = true;
	}

	public void setStruct() {
		isStruct = true;
	}

	public void setTemplate() {
		isTemplate = true;
	}

	public void setUnion() {
		isUnion = true;
	}

	public void setCoclass() {
		isCoclass = true;
	}

	public void setCointerface() {
		isCointerface = true;
	}

	public void setUnsigned() {
		isUnsigned = true;
	}

	public void setUnaligned() {
		isUnaligned = true;
	}

	public boolean isUnaligned() {
		return isUnaligned;
	}

	public void setVarArgs() {
		isVarArgs = true;
	}

	public void setEnumType(String enumType) {
		this.enumType = enumType;
	}

	public void setRestrict() {
		isRestrict = true;
	}

	public boolean isRestrict() {
		return isRestrict;
	}

	public boolean isArray() {
		return arrayDimensions > 0;
	}

	public boolean isClass() {
		return isClass;
	}

	public boolean isComplex() {
		return isComplex;
	}

	public boolean isEnum() {
		return isEnum;
	}

	public boolean isPointer() {
		return pointerLevels > 0;
	}

	public boolean isPointer64() {
		return isPointer64;
	}

	public boolean isReference() {
		return isReference;
	}

	public boolean isSigned() {
		return isSigned;
	}

	public boolean isStruct() {
		return isStruct;
	}

	public boolean isTemplate() {
		return isTemplate;
	}

	public boolean isUnion() {
		return isUnion;
	}

	public boolean isCoclass() {
		return isCoclass;
	}

	public boolean isCointerface() {
		return isCointerface;
	}

	public boolean isUnsigned() {
		return isUnsigned;
	}

	public boolean isVarArgs() {
		return isVarArgs;
	}

	public boolean isVoid() {
		return VOID.equals(getName());
	}

//	public boolean isVolatile() {
//		return isVolatile;
//	}
//
	public String setEnumType() {
		return enumType;
	}

	public String getBasedName() {
		return basedName;
	}

	public void setBasedName(String basedName) {
		this.basedName = basedName;
	}

	public String getMemberScope() {
		return memberScope;
	}

	public void setMemberScope(String memberScope) {
		this.memberScope = memberScope;
	}

	public boolean isPrimitive() {
		boolean isPrimitiveDT =
			!isArray() && !isClass && !isComplex && !isEnum && !isPointer() && !isPointer64 &&
				!isSigned && !isTemplate && !isUnion && !isCoclass && !isCointerface && !isVarArgs;
		if (isPrimitiveDT) {
			for (String primitiveNames : PRIMITIVES) {
				if (getName().equals(primitiveNames)) {
					return true;
				}
			}
		}
		return false;
	}

	@Override
	public String getSignature() {
		StringBuilder buffer = new StringBuilder();

		if (isUnion) {
			buffer.append(UNION + SPACE);
		}
		if (isStruct) {
			buffer.append(STRUCT + SPACE);
		}
		if (isEnum) {
			buffer.append(ENUM + SPACE);
			if ((enumType != null) && !("int".equals(enumType))) {
				buffer.append(enumType + SPACE);
			}
		}
		if (isClass) {
			buffer.append(CLASS + SPACE);
		}
		if (isCoclass) {
			buffer.append(COCLASS + SPACE);
		}
		if (isCointerface) {
			buffer.append(COINTERFACE + SPACE);
		}
		if (isComplex) {
			buffer.append(COMPLEX + SPACE);
		}
		if (isSigned) {
			buffer.append(SIGNED + SPACE);
		}
		if (isUnsigned) {
			buffer.append(UNSIGNED + SPACE);
		}

		if (getNamespace() != null) {
			buffer.append(getNamespace().getNamespaceString());
			buffer.append("::");
		}

		buffer.append(getDemangledName());

		if (getTemplate() != null) {
			buffer.append(getTemplate().toTemplate());
		}

		if (isConst()) {
			buffer.append(SPACE + CONST);
		}

		if (isVolatile()) {
			buffer.append(SPACE + VOLATILE);
		}

		if (basedName != null) {
			buffer.append(SPACE + basedName);
		}

		if ((memberScope != null) && (memberScope.length() != 0)) {
			buffer.append(SPACE + memberScope + "::");
		}

		if (isUnaligned) {
			buffer.append(SPACE + UNALIGNED);
		}

		if (pointerLevels >= 1) {
			buffer.append(SPACE + PTR_NOTATION);
		}

		if (isReference) {
			buffer.append(SPACE + REF_NOTATION);
			if (isRValueReference) {
				buffer.append(REF_NOTATION); // &&
			}
		}

		// the order of __ptr64 and __restrict can vary--with fuzzing... 
		// but what is the natural "real symbol" order?
		if (isPointer64) {
			buffer.append(SPACE + PTR64);
		}

		if (isRestrict) {
			buffer.append(SPACE + RESTRICT);
		}

		for (int i = 1; i < pointerLevels; i++) {
			buffer.append(SPACE + PTR_NOTATION);
		}

		if (isArray()) {
			// only put subscript on if the name doesn't have it
			Matcher matcher = ARRAY_SUBSCRIPT_PATTERN.matcher(getName());
			if (!matcher.find()) {
				for (int i = 0; i < arrayDimensions; i++) {
					buffer.append(ARR_NOTATION);
				}
			}
		}
		return buffer.toString();
	}

	@Override
	public String toString() {
		return getSignature();
	}
}
