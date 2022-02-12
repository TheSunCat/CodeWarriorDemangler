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

import java.util.List;
import java.util.ArrayList;

/**
 * A class to represent a demangled function pointer
 */
public class DemangledFunctionPointer extends DemangledDataType {
	protected static final String DEFAULT_NAME_PREFIX = "FuncDef";
	
	protected String callingConvention; // __cdecl, __thiscall, etc.
	protected String modifier; // namespace::, etc.
	protected boolean isConstPointer;
	protected DemangledDataType returnType;
	protected List<DemangledDataType> parameters = new ArrayList<>();

	protected String parentName;
	protected boolean isTrailingPointer64;
	protected boolean isTrailingUnaligned;
	protected boolean isTrailingRestrict;
	
	/** display parens in front of parameter list */
	private boolean displayFunctionPointerSyntax = true;

	public DemangledFunctionPointer(String mangled, String originalDemangled) {
		super(mangled, originalDemangled, DEFAULT_NAME_PREFIX + nextId());
		
		incrementPointerLevels(); // a function pointer is 1 level by default
	}
	
	protected static int ID = 0;
	private synchronized static int nextId() {
		return ID++;
	}

	protected String getTypeString() {
		return "*";
	}
	
	/**
	 * Sets the return type
	 * @param returnType the return type
	 */
	public void setReturnType(DemangledDataType returnType) {
		this.returnType = returnType;
	}
	
	/**
	 * Adds a parameters to the end of the parameter list for this demangled function
	 * @param parameter the new parameter to add
	 */
	public void addParameter(DemangledDataType parameter) {
		parameters.add(parameter);
	}

	/**
	 * Signals whether to display function pointer syntax when there is no function name, which 
	 * is '{@code (*)}', such as found in this example '{@code void (*)()}'.  the default is true
	 * @param b true to display nameless function pointer syntax; false to not display 
	 */
	public void setDisplayDefaultFunctionPointerSyntax(boolean b) {
		this.displayFunctionPointerSyntax = b;
	}

	protected void addFunctionPointerParens(StringBuilder buffer, String s) {
		if (!displayFunctionPointerSyntax) {
			return;
		}

		buffer.append('(').append(s).append(')');
	}
	
	public String toSignature(String name) {
		StringBuilder buffer = new StringBuilder();
		StringBuilder buffer1 = new StringBuilder();
		String s = getConventionPointerNameString(name);

		addFunctionPointerParens(buffer1, s);

		buffer1.append('(');
		for (int i = 0; i < parameters.size(); ++i) {
			buffer1.append(parameters.get(i).getSignature());
			if (i < parameters.size() - 1) {
				buffer1.append(',');
			}
		}
		buffer1.append(')');

		if (returnType instanceof DemangledFunctionPointer) {
			DemangledFunctionPointer dfp = (DemangledFunctionPointer) returnType;
			buffer.append(dfp.toSignature(buffer1.toString())).append(SPACE);
		}
		else if (returnType instanceof DemangledFunctionReference) {
			DemangledFunctionReference dfr = (DemangledFunctionReference) returnType;
			buffer.append(dfr.toSignature(buffer1.toString())).append(SPACE);
		}
		else if (returnType instanceof DemangledFunctionIndirect) {
			DemangledFunctionIndirect dfi = (DemangledFunctionIndirect) returnType;
			buffer.append(dfi.toSignature(buffer1.toString())).append(SPACE);
		}
		else {
			buffer.append(returnType.getSignature()).append(SPACE);
			buffer.append(buffer1);
		}

		if (isConst()) {
			if (buffer.length() > 2) {
				buffer.append(SPACE);
			}
			buffer.append(CONST);
		}

		if (isVolatile()) {
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

		return buffer.toString();
	}
	
	protected String getConventionPointerNameString(String name) {
		StringBuilder buffer = new StringBuilder();
		buffer.append(callingConvention == null ? "" : callingConvention);

		StringBuilder typeBuffer = new StringBuilder();
		int pointerLevels = getPointerLevels();
		if (pointerLevels > 0) {

			addParentName(typeBuffer);

			for (int i = 0; i < pointerLevels; ++i) {
				typeBuffer.append(getTypeString());
			}
		}

		if (!typeBuffer.isEmpty()) {

			if (!callingConvention.isEmpty()) {
				buffer.append(SPACE);
			}

			buffer.append(typeBuffer);
		}

		addModifier(buffer);

		if (isConstPointer) {
			buffer.append(CONST);
		}

		if (isPointer64()) {
			if (buffer.length() > 2) {
				buffer.append(SPACE);
			}
			buffer.append(PTR64);
		}

		if (name != null) {
			if ((buffer.length() > 0) && (buffer.charAt(buffer.length() - 1) != SPACE)) {
				buffer.append(SPACE);
			}
			buffer.append(name);
		}

		return buffer.toString();
	}
	
	protected void addParentName(StringBuilder buffer) {
		if (parentName == null) {
			return;
		}

		if (parentName.startsWith(DEFAULT_NAME_PREFIX)) {
			return;
		}

		if (buffer.length() > 2) {
			char lastChar = buffer.charAt(buffer.length() - 1);
			if (SPACE != lastChar) {
				buffer.append(SPACE);
			}
		}
		buffer.append(parentName).append("::");
	}
	
	private void addModifier(StringBuilder buffer) {
		if (modifier.isEmpty()) {
			return;
		}

		//
		// Guilty knowledge: in many cases the 'modifier' is the same as the type string.  Further,
		// when we print signatures, we will print the type string if there are pointer levels. To
		// prevent duplication, do not print the modifier when it matches the type string and we
		// will be printing the type string (which is printed when there are pointer levels).
		//
		if (modifier.equals(getTypeString()) &&
			getPointerLevels() > 0) {
			return;
		}

		if (buffer.length() > 2) {
			buffer.append(SPACE);
		}
		buffer.append(modifier);
	}
}
