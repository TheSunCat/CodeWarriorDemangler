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

import java.util.regex.Pattern;
/**
 * A class to represent a demangled object.
 */
public abstract class DemangledObject implements Demangled {

	protected static final String SPACE = " ";
	protected static final Pattern SPACE_PATTERN = Pattern.compile(SPACE);

	protected static final String NAMESPACE_SEPARATOR = "::";
	protected static final String EMPTY_STRING = "";

	protected final String mangled; // original mangled string
	protected final String originalDemangled;
	protected String specialPrefix;
	protected Demangled namespace;
	protected String visibility;//public, protected, etc.

	//TODO: storageClass refers to things such as "static" but const and volatile are
	// typeQualifiers.  Should change this everywhere(?).
	protected String storageClass; //const, volatile, etc

	//TODO: see above regarding this belonging to the "true" storageClass items.
	protected boolean isStatic;

	//TODO: determine what type of keyword this is (not type qualifier or storage class).
	protected boolean isVirtual;
	private String demangledName;
	private String name;
	private boolean isConst;
	private boolean isVolatile;
	private boolean isPointer64;

	protected boolean isThunk;
	protected boolean isUnaligned;
	protected boolean isRestrict;
	protected String basedName;
	protected String memberScope;

	private String plateComment;

	// Status of mangled String converted successfully to demangled String
	private boolean demangledNameSucceeded = false;

	DemangledObject(String mangled, String originalDemangled) {
		this.mangled = mangled;
		this.originalDemangled = originalDemangled;
	}

	@Override
	public String getDemangledName() {
		return demangledName;
	}

	@Override
	public String getName() {
		return name;
	}

	public boolean isConst() {
		return isConst;
	}

	public void setConst(boolean isConst) {
		this.isConst = isConst;
	}

	public boolean isVolatile() {
		return isVolatile;
	}

	public void setVolatile(boolean isVolatile) {
		this.isVolatile = isVolatile;
	}

	public boolean isPointer64() {
		return isPointer64;
	}

	public void setPointer64(boolean isPointer64) {
		this.isPointer64 = isPointer64;
	}

	public boolean isStatic() {
		return isStatic;
	}

	public void setStatic(boolean isStatic) {
		this.isStatic = isStatic;
	}

	public boolean isVirtual() {
		return isVirtual;
	}

	public void setVirtual(boolean isVirtual) {
		this.isVirtual = isVirtual;
	}

	public boolean isThunk() {
		return isThunk;
	}

	public void setThunk(boolean isThunk) {
		this.isThunk = isThunk;
	}

	public void setUnaligned() {
		isUnaligned = true;
	}

	public boolean isUnaligned() {
		return isUnaligned;
	}

	public void setRestrict() {
		isRestrict = true;
	}

	public boolean isRestrict() {
		return isRestrict;
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

	/**
	 * Sets the name of the demangled object
	 * @param name the new name
	 */
	@Override
	public void setName(String name) {
		this.demangledName = name;
		this.name = name;
		if (name != null) {
			// Use safe name and omit common spaces where they are unwanted in names.
			// Trim leading/trailing whitespace which may have been improperly included by demangler
			this.name = name;
				//TODO DemanglerUtil.stripSuperfluousSignatureSpaces(name).trim().replace(' ', '_');
		}
		demangledNameSucceeded = !mangled.equals(name);
	}

	/**
	 * Returns the success state of converting a mangled String into a demangled String
	 * @return true succeeded creating demangled String
	 */
	public boolean demangledNameSuccessfully() {
		return demangledNameSucceeded;
	}

	@Override
	public String getMangledString() {
		return mangled;
	}

	@Override
	public String getOriginalDemangled() {
		return originalDemangled;
	}

	@Override
	public Demangled getNamespace() {
		return namespace;
	}

	@Override
	public void setNamespace(Demangled namespace) {
		this.namespace = namespace;
	}

	public String getVisibility() {
		return visibility;
	}

	public void setVisibilty(String visibility) {
		this.visibility = visibility;
	}

	public String getStorageClass() {
		return storageClass;
	}

	public void setStorageClass(String storageClass) {
		this.storageClass = storageClass;
	}

	public String getSpecialPrefix() {
		return specialPrefix;
	}

	public void setSpecialPrefix(String special) {
		this.specialPrefix = special;
	}

	/**
	 * Returns a complete signature for the demangled symbol.
	 * <br>For example:
	 *            "unsigned long foo"
	 *            "unsigned char * ClassA::getFoo(float, short *)"
	 *            "void * getBar(int **, MyStruct &amp;)"
	 * <br><b>Note: based on the underlying mangling scheme, the
	 * return type may or may not be specified in the signature.</b>
	 * @param format true if signature should be pretty printed
	 * @return a complete signature for the demangled symbol
	 */
	public abstract String getSignature(boolean format);

	@Override
	public final String getSignature() {
		return getSignature(false);
	}

	@Override
	public String getNamespaceName() {
		return getName();
	}

	@Override
	public String toString() {
		return getSignature(false);
	}

	@Override
	public String getNamespaceString() {
		StringBuilder buffer = new StringBuilder();
		if (namespace != null) {
			buffer.append(namespace.getNamespaceString());
			buffer.append("::");
		}
		buffer.append(getNamespaceName());
		return buffer.toString();
	}

	/**
	 * Sets the plate comment to be used if the {@link #getOriginalDemangled()} string is not 
	 * available
	 * 
	 * @param plateComment the plate comment text
	 */
	public void setBackupPlateComment(String plateComment) {
		this.plateComment = plateComment;
	}

	/**
	 * Creates descriptive text that is intended to be used as documentation.  The text defaults
	 * to the original demangled text.  If that is not available, then any text set by
	 * {@link #setBackupPlateComment(String)} will be used.  The last choice for this text is
	 * the signature generated by {@link #getSignature(boolean)}.
	 * 
	 * @return the text
	 */
	protected String generatePlateComment() {
		if (originalDemangled != null) {
			return originalDemangled;
		}
		return (plateComment == null) ? getSignature(true) : plateComment;
	}
}
