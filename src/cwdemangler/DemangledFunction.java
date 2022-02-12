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

import java.util.*;

/**
 * A class to represent a demangled function.
 */
public class DemangledFunction extends DemangledObject {

	public static final String VOLATILE = "volatile";
	public static final String CONST = "const";
	public final static String PTR64 = "__ptr64";
	public static final String UNALIGNED = "__unaligned";
	public static final String RESTRICT = "__restrict";

	protected DemangledDataType returnType;
	protected String callingConvention;// __cdecl, __thiscall, etc.
	protected boolean thisPassedOnStack = true;
	protected List<DemangledDataType> parameters = new ArrayList<>();
	protected DemangledTemplate template;
	protected boolean isOverloadedOperator = false;

	/** Special constructor where it has a templated type before the parameter list */
	private String templatedConstructorType;

	private boolean isTrailingConst;
	private boolean isTrailingVolatile;
	private boolean isTrailingPointer64;
	private boolean isTrailingUnaligned;
	private boolean isTrailingRestrict;
	private boolean isTypeCast;
	private String throwAttribute;

	public DemangledFunction(String mangled, String originalDemangled, String name) {
		super(mangled, originalDemangled);
		setName(name);
	}

	/**
	 * Sets the function return type.
	 * @param returnType the function return type
	 */
	public void setReturnType(DemangledDataType returnType) {
		this.returnType = returnType;
	}

	/**
	 * Sets the function calling convention. For example, "__cdecl".
	 * @param callingConvention the function calling convention
	 */
	public void setCallingConvention(String callingConvention) {
		this.callingConvention = callingConvention;
	}

	public void setTemplate(DemangledTemplate template) {
		this.template = template;
	}

	public DemangledTemplate getTemplate() {
		return template;
	}

	/**
	 * Sets whether this demangled function represents
	 * an overloaded operator. For example, "operator+()".
	 * @param isOverloadedOperator true if overloaded operator
	 */
	public void setOverloadedOperator(boolean isOverloadedOperator) {
		this.isOverloadedOperator = isOverloadedOperator;
	}

	public void addParameter(DemangledDataType parameter) {
		parameters.add(parameter);
	}

	public List<DemangledDataType> getParameters() {
		return new ArrayList<>(parameters);
	}

	/**
	 * Returns the return type or null, if unspecified.
	 * @return the return type or null, if unspecified
	 */
	public DemangledDataType getReturnType() {
		return returnType;
	}

	/**
	 * Returns the calling convention or null, if unspecified.
	 * @return the calling convention or null, if unspecified
	 */
	public String getCallingConvention() {
		return callingConvention;
	}

	/**
	 * Special constructor where it has a templated type before the parameter list
	 * @param type the type
	 */
	public void setTemplatedConstructorType(String type) {
		this.templatedConstructorType = type;
	}

	public boolean isTrailingConst() {
		return isTrailingConst;
	}

	public void setTrailingConst() {
		isTrailingConst = true;
	}

	public boolean isTrailingVolatile() {
		return isTrailingVolatile;
	}

	public void setTrailingVolatile() {
		isTrailingVolatile = true;
	}

	public boolean isTrailingPointer64() {
		return isTrailingPointer64;
	}

	public void setTrailingPointer64() {
		isTrailingPointer64 = true;
	}

	public boolean isTrailingUnaligned() {
		return isTrailingUnaligned;
	}

	public void setTrailingUnaligned() {
		isTrailingUnaligned = true;
	}

	public boolean isTrailingRestrict() {
		return isTrailingRestrict;
	}

	public void setTrailingRestrict() {
		isTrailingRestrict = true;
	}

	public boolean isTypeCast() {
		return isTypeCast;
	}

	public void setTypeCast() {
		isTypeCast = true;
	}

	public void setThrowAttribute(String throwAttribute) {
		this.throwAttribute = throwAttribute;
	}

	@Override
	public String getSignature(boolean format) {
		StringBuilder buffer = new StringBuilder();

		if (!(returnType instanceof DemangledFunctionPointer)) {
			buffer.append(specialPrefix == null ? "" : specialPrefix + " ");
			if (isThunk) {
				buffer.append("[thunk]:");
			}
			buffer.append(
				visibility == null || "global".equals(visibility) ? "" : visibility + " ");
			if (isVirtual) {
				buffer.append("virtual ");
			}
			if (isStatic) {
				buffer.append("static ");
			}
			if (!isTypeCast()) {
				buffer.append(returnType == null ? "" : returnType.getSignature() + " ");
			}
		}

		buffer.append(callingConvention == null ? "" : callingConvention + " ");
		if (namespace != null) {
			buffer.append(namespace.getNamespaceString());
			buffer.append(NAMESPACE_SEPARATOR);
		}

		buffer.append(getDemangledName());
		if (isTypeCast()) {
			buffer.append(returnType == null ? "" : " " + returnType.getSignature() + " ");
		}

		if (template != null) {
			buffer.append(template.toTemplate());
		}

		if (templatedConstructorType != null) {
			buffer.append('<').append(templatedConstructorType).append('>');
		}

		addParameters(buffer, format);

		buffer.append(storageClass == null ? "" : " " + storageClass);

		if (returnType instanceof DemangledFunctionPointer) {
			DemangledFunctionPointer funcPtr = (DemangledFunctionPointer) returnType;
			String partialSig = funcPtr.toSignature(buffer.toString());
			buffer = new StringBuilder();
			buffer.append(specialPrefix == null ? "" : specialPrefix + " ");
			buffer.append(
				visibility == null || "global".equals(visibility) ? "" : visibility + " ");
			if (isVirtual) {
				buffer.append("virtual ");
			}
			buffer.append(partialSig);
		}

		if (isTrailingConst()) {
			if (buffer.length() > 2) {
				buffer.append(SPACE);
			}
			buffer.append(CONST);
		}
		if (isTrailingVolatile()) {
			if (buffer.length() > 2) {
				buffer.append(SPACE);
			}
			buffer.append(VOLATILE);
		}
		if (isTrailingUnaligned) {
			if (buffer.length() > 2) {
				buffer.append(SPACE);
			}
			buffer.append(UNALIGNED);
		}
		if (isTrailingPointer64) {
			if (buffer.length() > 2) {
				buffer.append(SPACE);
			}
			buffer.append(PTR64);
		}
		if (isTrailingRestrict) {
			if (buffer.length() > 2) {
				buffer.append(SPACE);
			}
			buffer.append(RESTRICT);
		}
		if (throwAttribute != null) {
			if (buffer.length() > 2) {
				buffer.append(SPACE);
			}
			buffer.append(throwAttribute);
		}

		return buffer.toString();
	}

	
	protected void addParameters(StringBuilder buffer, boolean format) {
		Iterator<DemangledDataType> paramIterator = parameters.iterator();
		buffer.append('(');
		int padLength = format ? buffer.length() : 0;
		
		String pad = "";
		for(int i = 0; i < padLength; i++)
			pad += ' ';
		
		if (!paramIterator.hasNext()) {
			buffer.append("void");
		}

		while (paramIterator.hasNext()) {
			buffer.append(paramIterator.next().getSignature());
			if (paramIterator.hasNext()) {
				buffer.append(',');
				if (format) {
					buffer.append('\n');
				}
				buffer.append(pad);
			}
		}

		buffer.append(')');
	}

	@Override
	public String getNamespaceName() {
		return getName() + getParameterString();
	}

	public String getParameterString() {
		StringBuffer buffer = new StringBuffer();
		buffer.append('(');
		Iterator<DemangledDataType> dditer = parameters.iterator();
		while (dditer.hasNext()) {
			buffer.append(dditer.next().getSignature());
			if (dditer.hasNext()) {
				buffer.append(',');
			}
		}
		buffer.append(')');
		return buffer.toString();
	}
}
