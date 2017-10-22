package go_javad

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// Disassemble reads and disassembles a binary class and fetches internal and library method calls within the code
//
// Steps:
// 1. Read the binary class file
// 2. Disassemble the class file code operations
// 3. Fetch internal and library method calls from the code
func Disassemble(data []byte) (methodCalls JVMethods, err error) {
	c, err := newJavaClassFile(data)
	if err != nil {
		return methodCalls, err
	}
	for _, m := range c.methods {
		for _, attr := range m.attributes {
			// Fetch constant information
			cInfo, err := c.constantInfo(attr.attributeNameIndex)
			if err != nil {
				return methodCalls, fmt.Errorf("failed to fetch constant, %v", err)
			}
			// Analyse only code attributes
			// For all available attribute types see: https://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.7
			if cInfo.info != "Code" {
				continue
			}
			code, err := newCodeAttribute(attr.info, c.constantInfo)
			if err != nil {
				return methodCalls, fmt.Errorf("failed to create code attr object, %v", err)
			}
			mc, err := code.methodCalls()
			if err != nil {
				name, _ := c.constantInfo(m.nameIndex)
				flags, _ := translateFlags(m.accessFlags)
				return methodCalls, fmt.Errorf("failed to inspect code attribute for %s method %s: %v", flags, name, err)
			}
			methodCalls.internal = append(methodCalls.internal, mc.internal...)
			methodCalls.library = append(methodCalls.library, mc.library...)
		}
	}
	return methodCalls, nil
}

const (
	// Integers byte sizes
	jvmSizeOfUint64 = 8
	jvmSizeOfUint32 = 4
	jvmSizeOfInt32  = 4
	jvmSizeOfUint16 = 2
	jvmSizeOfInt16  = 2
	jvmSizeOfUint8  = 1
	jvmSizeOfInt8   = 1

	// Constant pool
	// see: https://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.4
	constTypeUtf8            = "Utf8"
	constTypeInt             = "Int"
	constTypeFloat           = "Float"
	constTypeLong            = "Long"
	constTypeDouble          = "Double"
	constTypeClass           = "Class"
	constTypeString          = "String"
	constTypeField           = "Field"
	constTypeMethod          = "Method"
	constTypeInterfaceMethod = "InterfaceMethod"
	constTypeNameAndType     = "NameAndType"
	constTypeMethodHandle    = "MethodHandle"
	constTypeMethodType      = "MethodType"
	constTypeInvokeDynamic   = "InvokeDynamic"
	constTypeNone            = "None"

	// We do not support old jdk version (<1.1) for class versions under 45.3 which uses shorter bytes
	// representation for the codeAttribute entries. i.e., maxStack type would be uint8 instead of uint16
	minMajorSupportedVersion = 45
	minMinorSupportedVersion = 3
)

var (
	// jvmConstsStackOrder is a list of constants ordered by the JVM constant stack order
	jvmConstsStackOrder = []string{constTypeNone, constTypeUtf8, constTypeNone, constTypeInt, constTypeFloat, constTypeLong, constTypeDouble, constTypeClass, constTypeString, constTypeField, constTypeMethod, constTypeInterfaceMethod, constTypeNameAndType, constTypeNone, constTypeNone, constTypeMethodHandle, constTypeMethodType, constTypeNone, constTypeInvokeDynamic}
	// jvmOpNames is a list of the JVM operator names
	jvmOpNames = []string{"nop", "aconst_null", "iconst_m1", "iconst_0", "iconst_1", "iconst_2", "iconst_3", "iconst_4", "iconst_5", "lconst_0", "lconst_1", "fconst_0", "fconst_1", "fconst_2", "dconst_0", "dconst_1", "bipush", "sipush", "ldc", "ldc_w", "ldc2_w", "iload", "lload", "fload", "dload", "aload", "iload_0", "iload_1", "iload_2", "iload_3", "lload_0", "lload_1", "lload_2", "lload_3", "fload_0", "fload_1", "fload_2", "fload_3", "dload_0", "dload_1", "dload_2", "dload_3", "aload_0", "aload_1", "aload_2", "aload_3", "iaload", "laload", "faload", "daload", "aaload", "baload", "caload", "saload", "istore", "lstore", "fstore", "dstore", "astore", "istore_0", "istore_1", "istore_2", "istore_3", "lstore_0", "lstore_1", "lstore_2", "lstore_3", "fstore_0", "fstore_1", "fstore_2", "fstore_3", "dstore_0", "dstore_1", "dstore_2", "dstore_3", "astore_0", "astore_1", "astore_2", "astore_3", "iastore", "lastore", "fastore", "dastore", "aastore", "bastore", "castore", "sastore", "pop", "pop2", "dup", "dup_x1", "dup_x2", "dup2", "dup2_x1", "dup2_x2", "swap", "iadd", "ladd", "fadd", "dadd", "isub", "lsub", "fsub", "dsub", "imul", "lmul", "fmul", "dmul", "idiv", "ldiv", "fdiv", "ddiv", "irem", "lrem", "frem", "drem", "ineg", "lneg", "fneg", "dneg", "ishl", "lshl", "ishr", "lshr", "iushr", "lushr", "iand", "land", "ior", "lor", "ixor", "lxor", "iinc", "i2l", "i2f", "i2d", "l2i", "l2f", "l2d", "f2i", "f2l", "f2d", "d2i", "d2l", "d2f", "i2b", "i2c", "i2s", "lcmp", "fcmpl", "fcmpg", "dcmpl", "dcmpg", "ifeq", "ifne", "iflt", "ifge", "ifgt", "ifle", "if_icmpeq", "if_icmpne", "if_icmplt", "if_icmpge", "if_icmpgt", "if_icmple", "if_acmpeq", "if_acmpne", "goto", "jsr", "ret", "tableswitch", "lookupswitch", "ireturn", "lreturn", "freturn", "dreturn", "areturn", "return", "getstatic", "putstatic", "getfield", "putfield", "invokevirtual", "invokespecial", "invokestatic", "invokeinterface", "invokedynamic", "new", "newarray", "anewarray", "arraylength", "athrow", "checkcast", "instanceof", "monitorenter", "monitorexit", "wide", "multianewarray", "ifnull", "ifnonnull", "goto_w", "jsr_w"}
	// javaMethodFlags is the methods access flags translation from bits to name
	// See: https://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.6 (Table 4.5. Method access and property flags)
	jvmMethodFlags = map[uint16]string{
		0x0001: "public",
		0x0002: "private",
		0x0004: "protected",
		0x0008: "static",
		0x0010: "final",
		0x0020: "synchronized",
		0x0040: "bridge",
		0x0080: "varargs",
		0x0100: "native",
		0x0200: "interface",
		0x0400: "abstract",
		0x0800: "strict",
		0x1000: "synthetic",
		0x2000: "annotation",
		0x4000: "enum",
		0x8000: "mandated",
	}
)

// JVMethods holds the library and internal method calls within a class file code
type JVMethods struct {
	library  []jvmMethodDescriptor // library is a list of all library method calls
	internal []jvmMethodDescriptor // internal is a list ofall internal method calls
}

// jvmMethodDescriptor is a descriptor of a code method call
type jvmMethodDescriptor struct {
	op     string // op is the operator of the call
	path   string // path is the method package path
	method string // method is the method name
	args   string // args are the args that were used to invoke the method
}

// constantInfo describes the java Constant data structure
// see: https://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.4
type constantInfo struct {
	tag  string   // tag is the constant type value
	info string   // info is the constant value
	refs []uint16 // refs is the constant references. see: https://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.4.2
}

// attributeInfo describes the java Attribute data structure
// see: https://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.7
type attributeInfo struct {
	attributeNameIndex uint16 // attributeNameIndex is the valid index into the constant pool table
	attributeLength    uint32 // attributeLength is the attribute length
	info               []byte // info is the attribute raw data
}

// componentInfo describes the java Method/Field data structure
//
// see:
// https://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.5
// https://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.6
type componentInfo struct {
	accessFlags     uint16          // accessFlags is the mask of flags used to denote access permission to and properties of this method
	nameIndex       uint16          // nameIndex is the valid index into the constant pool table
	descriptorIndex uint16          // descriptorIndex is the valid index of the descriptor in the constant pool table
	attributesCount uint16          // attributesCount is the number of additional attributes in this component
	attributes      []attributeInfo // attributes is the list of attributes information
}

// classFile describes the java class file structure as defined in the jvm specs
// see: https://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.1
type classFile struct {
	magic             uint32          // magic is the class magic number
	minorVersion      uint16          // minorVersion is the class version minor
	majorVersion      uint16          // majorVersion is the class version major
	constantPoolCount uint16          // constantPoolCount is the number of constants in the class file (equal to the number of entries in the constant pool table plus one)
	constantPool      []constantInfo  // constantPool is the table of constants in the class file
	accessFlags       uint16          // accessFlags is the mask of flags used to denote access permissions to and properties of this class or interface
	thisClass         uint16          // thisClass is a valid index into the constant_pool table
	superClass        uint16          // superClass is a valid index into the constant_pool table
	interfacesCount   uint16          // interfacesCount is the number of interfaces in the class file
	interfaces        []uint16        // interfaces is a list of valid indexes into the constant_pool table
	fieldsCount       uint16          // fieldsCount is the number of field structures in the class file
	fields            []componentInfo // fields is the list of field components
	methodsCount      uint16          // methodsCount is the number of methods in the class file
	methods           []componentInfo // methods is the list of methods components
	attributesCount   uint16          // attributesCount is the number of global attributes in the class file
	attributes        []attributeInfo // attributes is the list of the attributes information
}

// newJavaClassFile loads a class file raw data into a class structure
//
// REMARK: All the java class struct fields are populated according to the java class file structure in order to
// keep coherency with the original structure implementation.
func newJavaClassFile(data []byte) (*classFile, error) {
	// Create a bytecode reader
	reader := newByteCodeReader(data)
	c := &classFile{}
	var err error
	if c.magic, err = reader.readU32(); err != nil {
		return nil, err
	}
	// Verify magic number and class version
	if c.magic != 0xcafebabe {
		return nil, fmt.Errorf("not a valid class file, magic number incorrect")
	}
	if c.minorVersion, err = reader.readU16(); err != nil {
		return nil, err
	}
	if c.majorVersion, err = reader.readU16(); err != nil {
		return nil, err
	}
	if c.majorVersion < minMajorSupportedVersion && c.minorVersion < minMinorSupportedVersion {
		return nil, fmt.Errorf("class file version is %d.%d, should be >%d.%d", c.majorVersion, c.minorVersion, minMajorSupportedVersion, minMinorSupportedVersion)
	}
	if c.constantPoolCount, err = reader.readU16(); err != nil {
		return nil, err
	}
	// Constant pool always starts with blank constant
	c.constantPool = append(c.constantPool, constantInfo{tag: "", info: "", refs: nil})
	// Populate class constant pool
	for len(c.constantPool) < int(c.constantPoolCount) {
		constInfo := constantInfo{}
		constIndex, err := reader.readU8()
		if err != nil {
			return nil, err
		}
		if len(jvmConstsStackOrder) < int(constIndex) {
			return nil, fmt.Errorf("failed to find const at %d, index out of range", constIndex)
		}
		constInfo.tag = jvmConstsStackOrder[constIndex]
		switch constInfo.tag {
		case constTypeUtf8:
			infoLength, err := reader.readU16()
			if err != nil {
				return nil, err
			}
			infoBytes, err := reader.readBytes(int(infoLength))
			if err != nil {
				return nil, err
			}
			constInfo.info = string(infoBytes)
			break
		case constTypeInt, constTypeFloat:
			num, err := reader.readU32()
			if err != nil {
				return nil, err
			}
			constInfo.info = string(num)
			break
		case constTypeLong, constTypeDouble:
			num, err := reader.readU64()
			if err != nil {
				return nil, err
			}
			constInfo.info = string(num)
			break
		case constTypeMethodHandle:
			index, err := reader.readU8()
			if err != nil {
				return nil, err
			}
			constInfo.info = string(index)
			ref, err := reader.readU16()
			if err != nil {
				return nil, err
			}
			constInfo.refs = append(constInfo.refs, ref)
			break
		case constTypeClass, constTypeString, constTypeMethodType:
			ref, err := reader.readU16()
			if err != nil {
				return nil, err
			}
			constInfo.refs = append(constInfo.refs, ref)
			break
		default:
			// On default there are two references
			ref, err := reader.readU16()
			if err != nil {
				return nil, err
			}
			constInfo.refs = append(constInfo.refs, ref)
			// Read reference #2
			ref, err = reader.readU16()
			if err != nil {
				return nil, err
			}
			constInfo.refs = append(constInfo.refs, ref)
		}
		c.constantPool = append(c.constantPool, constInfo)
		if constInfo.tag == constTypeLong || constInfo.tag == constTypeDouble {
			// Constant pool of type long and double always followed by blank constant
			c.constantPool = append(c.constantPool, constantInfo{tag: "", info: "", refs: nil})
		}
	}
	if c.accessFlags, err = reader.readU16(); err != nil {
		return nil, err
	}
	if c.thisClass, err = reader.readU16(); err != nil {
		return nil, err
	}
	if c.superClass, err = reader.readU16(); err != nil {
		return nil, err
	}
	if c.interfacesCount, err = reader.readU16(); err != nil {
		return nil, err
	}
	for i := 0; i < int(c.interfacesCount); i++ {
		index, err := reader.readU16()
		if err != nil {
			return nil, err
		}
		c.interfaces = append(c.interfaces, index)
	}
	if c.fieldsCount, err = reader.readU16(); err != nil {
		return nil, err
	}
	// Populate fields
	if c.fields, err = c.componentInfo(reader, c.fieldsCount); err != nil {
		return nil, err
	}
	if c.methodsCount, err = reader.readU16(); err != nil {
		return nil, err
	}
	// Populate methods
	if c.methods, err = c.componentInfo(reader, c.methodsCount); err != nil {
		return nil, err
	}
	if c.attributesCount, err = reader.readU16(); err != nil {
		return nil, err
	}
	// Populate attributes
	for i := 0; i < int(c.attributesCount); i++ {
		a := attributeInfo{}
		if a.attributeNameIndex, err = reader.readU16(); err != nil {
			return nil, err
		}
		if a.attributeLength, err = reader.readU32(); err != nil {
			return nil, err
		}
		length := a.attributeLength
		if len(c.constantPool) < int(a.attributeNameIndex) &&
			c.constantPool[a.attributeNameIndex].tag == constTypeUtf8 &&
			c.constantPool[a.attributeNameIndex].info == "InnerClasses" {
			stringLen, err := reader.peekU16()
			if err != nil {
				return nil, err
			}
			length = uint32(stringLen*8 + 2)
		}
		if a.info, err = reader.readBytes(int(length)); err != nil {
			return nil, err
		}
		c.attributes = append(c.attributes, a)
	}
	return c, nil
}

// componentInfo reads the method or field information
func (c *classFile) componentInfo(reader *byteCodeReader, count uint16) (infos []componentInfo, err error) {
	for i := 0; i < int(count); i++ {
		f := componentInfo{}
		if f.accessFlags, err = reader.readU16(); err != nil {
			return nil, err
		}
		if f.nameIndex, err = reader.readU16(); err != nil {
			return nil, err
		}
		if f.descriptorIndex, err = reader.readU16(); err != nil {
			return nil, err
		}
		if f.attributesCount, err = reader.readU16(); err != nil {
			return nil, err
		}
		for j := 0; j < int(f.attributesCount); j++ {
			a := attributeInfo{}
			if a.attributeNameIndex, err = reader.readU16(); err != nil {
				return nil, err
			}
			if a.attributeLength, err = reader.readU32(); err != nil {
				return nil, err
			}
			if a.info, err = reader.readBytes(int(a.attributeLength)); err != nil {
				return nil, err
			}
			f.attributes = append(f.attributes, a)
		}
		infos = append(infos, f)
	}
	return infos, nil
}

// constantInfo retrieves the constant info from the constant pool by the given index
func (c *classFile) constantInfo(i uint16) (*constantInfo, error) {
	if len(c.constantPool) < int(i) {
		return nil, fmt.Errorf("no constant at %d, index out of range.", i)
	}
	return &c.constantPool[i], nil
}

// translateFlags gets field or method flags (public, private, static, etc.) numeric representation and translates it
// to string by the given translator.
// For example: 0x0001 will be translated to "public"
func translateFlags(flags uint16) ([]string, error) {
	var translated []string
	for k, v := range jvmMethodFlags {
		// Check if flag is on with bitwise and.
		// For example, lets take a "private static method". private flag is 0x0002 (..00010 in binary) and static flag is 0x0008 (..01000 in binary).
		// together they make ..01010 in binary representation. The loop iterations will go:
		// 0.  ..01010 & ..0001 -> no match
		// 1.  ..01010 & ..0010 -> match -> translator[0x0002] = "private"
		// 2.  ..01010 & ..0100 -> no match
		// 3.  ..01010 & ..1000 -> match -> translator[0x0008] = "static"
		// 4.  ..01010 & .10000 -> no match
		// ...
		// 15. ..01010 &  100.. -> no match
		if flags&k != 0 {
			translated = append(translated, v)
		}
	}
	return translated, nil
}

// exceptionInfo describes the java exception info structure
type exceptionInfo struct {
	startPc   uint16
	endPc     uint16
	handlerPc uint16
	catchPc   uint16
}

// codeAttribute describes the java Code_attribute structure as defined in the jvm specs
// see: https://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.7.3
type codeAttribute struct {
	constantInfo         func(i uint16) (*constantInfo, error) // constantInfo is the parent constant info getter
	maxStack             uint16
	maxLocals            uint16
	codeLength           uint32
	code                 []byte
	exceptionTableLength uint16
	exceptionTable       []exceptionInfo
	attributesCount      uint16
	attributes           []attributeInfo
}

// newCodeAttribute loads raw code data into a code structure
func newCodeAttribute(data []byte, constantInfo func(i uint16) (*constantInfo, error)) (*codeAttribute, error) {
	c := &codeAttribute{constantInfo: constantInfo}
	r := newByteCodeReader(data)
	var err error
	if c.maxStack, err = r.readU16(); err != nil {
		return nil, err
	}
	if c.maxLocals, err = r.readU16(); err != nil {
		return nil, err
	}
	if c.codeLength, err = r.readU32(); err != nil {
		return nil, err
	}
	if c.code, err = r.readBytes(int(c.codeLength)); err != nil {
		return nil, err
	}
	if c.exceptionTableLength, err = r.readU16(); err != nil {
		return nil, err
	}
	for i := 0; i < int(c.exceptionTableLength); i++ {
		e := exceptionInfo{}
		if e.startPc, err = r.readU16(); err != nil {
			return nil, err
		}
		if e.endPc, err = r.readU16(); err != nil {
			return nil, err
		}
		if e.handlerPc, err = r.readU16(); err != nil {
			return nil, err
		}
		if e.catchPc, err = r.readU16(); err != nil {
			return nil, err
		}
		c.exceptionTable = append(c.exceptionTable, e)
	}
	if c.attributesCount, err = r.readU16(); err != nil {
		return nil, err
	}
	for i := 0; i < int(c.attributesCount); i++ {
		a := attributeInfo{}
		if a.attributeNameIndex, err = r.readU16(); err != nil {
			return nil, err
		}
		if a.attributeLength, err = r.readU32(); err != nil {
			return nil, err
		}
		if a.info, err = r.readBytes(int(a.attributeLength)); err != nil {
			return nil, err
		}
		c.attributes = append(c.attributes, a)
	}
	return c, nil
}

// constant retrieves a class constant from the class constant pool by a given index
// For example, at a certain point in the code we have invokevirtual command on method <constant-index>.
// The constant index represents the index at the constant pool to retrieve the class path and method name.
func (c *codeAttribute) constant(idx uint16, tag []string, refsCount int) (*constantInfo, error) {
	info, err := c.constantInfo(idx)
	if err != nil {
		return info, err
	}
	// Verify tags list contains the info tag
	tagContains := false
	for _, t := range tag {
		if t == info.tag {
			tagContains = true
		}
	}
	if !tagContains {
		return info, fmt.Errorf("wrong reference type while inspecting invoked method, expected %q, got: %q", tag, info.tag)
	}
	if len(info.refs) != refsCount {
		return info, fmt.Errorf("insufficient reference count at constant %d", idx)
	}
	return info, nil
}

// methodCalls fetches the invoked methods throughout the code commands.
// Steps are basically going through the code commands and trace method calls
func (c *codeAttribute) methodCalls() (methodCalls JVMethods, err error) {
	r := newByteCodeReader(c.code)
	for (len(c.code) - r.offset) > 0 {
		offset := r.offset
		opIndex, err := r.readU8()
		if err != nil {
			return methodCalls, err
		}
		if len(jvmOpNames) <= int(opIndex) {
			return methodCalls, fmt.Errorf("unknown operation at %d, index out of range.", opIndex)
		}
		op := jvmOpNames[opIndex]
		// Move cursor recording to the operator size
		// see: https://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.9.1
		switch op {
		case "ifeq", "ifne", "iflt", "ifge", "ifgt", "ifle", "if_icmpeq", "if_icmpne", "if_icmplt", "if_icmpge", "if_icmpgt", "if_icmple", "if_acmpeq", "if_acmpne", "goto", "jsr", "ifnull", "ifnonnull":
			r.offset += jvmSizeOfUint16
			break
		case "goto_w", "jsr_w":
			r.offset += jvmSizeOfUint32
			break
		case "iload", "lload", "fload", "dload", "aload", "istore", "lstore", "fstore", "dstore", "astore", "ret":
			r.offset += jvmSizeOfUint8
			break
		case "new", "anewarray", "checkcast", "instanceof":
			r.offset += jvmSizeOfUint16
			break
		case "getstatic", "putstatic", "getfield", "putfield":
			r.offset += jvmSizeOfUint16
			break
		case "invokevirtual", "invokespecial", "invokestatic":
			cand := jvmMethodDescriptor{op: op}
			index, err := r.readU16()
			if err != nil {
				return methodCalls, err
			}
			var cInfo *constantInfo
			if cInfo, err = c.constant(index, []string{constTypeMethod, constTypeInterfaceMethod, constTypeField}, 2); err != nil {
				return methodCalls, fmt.Errorf("failed to fetch invoke constant, %v", err)
			}
			var reference, innerRef *constantInfo
			// Fetch the class reference
			if reference, err = c.constant(cInfo.refs[0], []string{constTypeClass}, 1); err != nil {
				return methodCalls, fmt.Errorf("failed to fetch class constant, %v", err)
			}
			if innerRef, err = c.constant(reference.refs[0], []string{constTypeUtf8}, 0); err != nil {
				return methodCalls, fmt.Errorf("failed to fetch class path constant, %v", err)
			}
			cand.path = innerRef.info
			// Fetch the name and type reference
			if reference, err = c.constant(cInfo.refs[1], []string{constTypeNameAndType}, 2); err != nil {
				return methodCalls, fmt.Errorf("failed to fetch name reference constant, %v", err)
			}
			// Fetch method name
			if innerRef, err = c.constant(reference.refs[0], []string{constTypeUtf8}, 0); err != nil {
				return methodCalls, fmt.Errorf("failed to fetch method name constant, %v", err)
			}
			cand.method = innerRef.info
			// Fetch method args
			if innerRef, err = c.constant(reference.refs[1], []string{constTypeUtf8}, 0); err != nil {
				return methodCalls, fmt.Errorf("failed to fetch args constant, %v", err)
			}
			cand.args = innerRef.info
			// Java library methods have the package prefix of java (i.e., java/io/PrintWriter)
			if strings.HasPrefix(cand.path, "java/") {
				methodCalls.library = append(methodCalls.library, cand)
			} else {
				methodCalls.internal = append(methodCalls.internal, cand)
			}
			break
		case "invokeinterface":
			r.offset += jvmSizeOfUint16 + jvmSizeOfUint8 + jvmSizeOfUint8
			break
		case "invokedynamic":
			r.offset += jvmSizeOfUint16 + jvmSizeOfUint16
			break
		case "ldc":
			r.offset += jvmSizeOfUint8
			break
		case "ldc_w", "ldc2_w":
			r.offset += jvmSizeOfUint16
			break
		case "multianewarray":
			r.offset += jvmSizeOfUint16 + jvmSizeOfUint8
			break
		case "bipush":
			r.offset += jvmSizeOfInt8
			break
		case "sipush":
			r.offset += jvmSizeOfInt16
			break
		case "iinc":
			r.offset += jvmSizeOfUint8 + jvmSizeOfInt8
			break
		case "wide":
			innerOpIndex, err := r.readU8()
			if err != nil {
				return methodCalls, err
			}
			if len(jvmOpNames) < int(innerOpIndex) {
				return methodCalls, fmt.Errorf("failed to find inner operation at %d, index out of range", innerOpIndex)
			}
			innerOp := jvmOpNames[innerOpIndex]
			r.offset += jvmSizeOfUint16
			if innerOp == "iinc" {
				r.offset += jvmSizeOfInt16
			}
			break
		case "newarray":
			r.offset += jvmSizeOfUint8
			break
		case "tableswitch":
			// When the code array is read into memory on a byte-addressable machine, if the first byte of the array is aligned on a 4-byte boundary,
			// the tableswitch and lookupswitch 32-bit offsets will be 4-byte aligned.
			// (Refer to the descriptions of those instructions for more information on the consequences of code array alignment.)
			// See: https://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.7.3
			bytesCount := (3 - offset) % 4
			// Golang modulus can return negative reminder
			if bytesCount < 0 {
				bytesCount += 4
			}
			r.offset += bytesCount + jvmSizeOfInt32
			low, err := r.readS32()
			if err != nil {
				return methodCalls, err
			}
			high, err := r.readS32()
			if err != nil {
				return methodCalls, err
			}
			for i := 0; i < (int(high) - int(low) + 1); i++ {
				r.offset += jvmSizeOfInt32
			}
			break
		case "lookupswitch":
			// See tableswitch comment
			// Also see: https://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.10.1.9.lookupswitch
			bytesCount := (3 - offset) % 4
			// Golang modulus can return negative reminder
			if bytesCount < 0 {
				bytesCount += 4
			}
			r.offset += bytesCount + jvmSizeOfInt32
			count, err := r.readS32()
			if err != nil {
				return methodCalls, err
			}
			r.offset += int(count) * (jvmSizeOfInt32 + jvmSizeOfInt32)
			break
		case "nop", "aconst_null", "iconst_m1", "iconst_0", "iconst_1", "iconst_2", "iconst_3", "iconst_4", "iconst_5", "lconst_0", "lconst_1", "fconst_0", "fconst_1", "fconst_2", "dconst_0", "dconst_1", "iload_0", "iload_1", "iload_2", "iload_3", "lload_0", "lload_1", "lload_2", "lload_3", "fload_0", "fload_1", "fload_2", "fload_3", "dload_0", "dload_1", "dload_2", "dload_3", "aload_0", "aload_1", "aload_2", "aload_3", "iaload", "laload", "faload", "daload", "aaload", "baload", "caload", "saload", "istore_0", "istore_1", "istore_2", "istore_3", "lstore_0", "lstore_1", "lstore_2", "lstore_3", "fstore_0", "fstore_1", "fstore_2", "fstore_3", "dstore_0", "dstore_1", "dstore_2", "dstore_3", "astore_0", "astore_1", "astore_2", "astore_3", "iastore", "lastore", "fastore", "dastore", "aastore", "bastore", "castore", "sastore", "pop", "pop2", "dup", "dup_x1", "dup_x2", "dup2", "dup2_x1", "dup2_x2", "swap", "iadd", "ladd", "fadd", "dadd", "isub", "lsub", "fsub", "dsub", "imul", "lmul", "fmul", "dmul", "idiv", "ldiv", "fdiv", "ddiv", "irem", "lrem", "frem", "drem", "ineg", "lneg", "fneg", "dneg", "ishl", "lshl", "ishr", "lshr", "iushr", "lushr", "iand", "land", "ior", "lor", "ixor", "lxor", "i2l", "i2f", "i2d", "l2i", "l2f", "l2d", "f2i", "f2l", "f2d", "d2i", "d2l", "d2f", "i2b", "i2c", "i2s", "lcmp", "fcmpl", "fcmpg", "dcmpl", "dcmpg", "ireturn", "lreturn", "freturn", "dreturn", "areturn", "return", "arraylength", "athrow", "monitorenter", "monitorexit":
			// No offset required
			break
		default:
			return methodCalls, fmt.Errorf("failed to inspect operator %s", op)
		}
	}
	return methodCalls, nil
}

// byteCodeReader is the class bytecode reader.
// The reader holds a cursor for the current position on the binary file, and moves the cursor on every read accordingly
type byteCodeReader struct {
	data   []byte
	offset int
}

var errIndexOutOfRange = errors.New("index out of range")

func newByteCodeReader(data []byte) *byteCodeReader {
	return &byteCodeReader{data: data}
}

// readU64 reads a unsigned int 64 size bytes stored in big endian sequence
func (r *byteCodeReader) readU64() (uint64, error) {
	if len(r.data) <= r.offset+jvmSizeOfUint64 {
		return 0, errIndexOutOfRange
	}
	res := binary.BigEndian.Uint64(r.data[r.offset : r.offset+jvmSizeOfUint64])
	r.offset += jvmSizeOfUint64
	return res, nil
}

// readU32 reads a unsigned int 32 size bytes stored in big endian sequence
func (r *byteCodeReader) readU32() (uint32, error) {
	if len(r.data) <= r.offset+jvmSizeOfUint32 {
		return 0, errIndexOutOfRange
	}
	res := binary.BigEndian.Uint32(r.data[r.offset : r.offset+jvmSizeOfUint32])
	r.offset += jvmSizeOfUint32
	return res, nil
}

// readS32 reads a signed int 64 size bytes stored in big endian sequence
func (r *byteCodeReader) readS32() (int32, error) {
	if len(r.data) <= r.offset+jvmSizeOfInt32 {
		return 0, errIndexOutOfRange
	}
	res := binary.BigEndian.Uint32(r.data[r.offset : r.offset+jvmSizeOfInt32])
	r.offset += jvmSizeOfInt32
	return int32(res), nil
}

// readU16 reads a unsigned int 16 size bytes stored in big endian sequence
func (r *byteCodeReader) readU16() (uint16, error) {
	if len(r.data) <= r.offset+jvmSizeOfUint16 {
		return 0, errIndexOutOfRange
	}
	res := binary.BigEndian.Uint16(r.data[r.offset : r.offset+jvmSizeOfUint16])
	r.offset += jvmSizeOfUint16
	return res, nil
}

// readU8 reads a unsigned int 8 size bytes stored in big endian sequence
func (r *byteCodeReader) readU8() (uint8, error) {
	if len(r.data) <= r.offset {
		return 0, errIndexOutOfRange
	}
	res := binary.BigEndian.Uint16([]byte{0x00, r.data[r.offset]})
	r.offset += jvmSizeOfUint8
	return uint8(res), nil
}

// readBytes reads an offset size sequence from the raw data
func (r *byteCodeReader) readBytes(offset int) ([]byte, error) {
	if len(r.data) < r.offset+offset {
		return nil, errIndexOutOfRange
	}
	bytes := r.data[r.offset : r.offset+offset]
	r.offset += offset
	return bytes, nil
}

// peekU16 peeks unsigned int 16 size bytes (without moving the cursor)
func (r *byteCodeReader) peekU16() (uint16, error) {
	if len(r.data) <= r.offset+jvmSizeOfUint16 {
		return 0, errIndexOutOfRange
	}
	return binary.BigEndian.Uint16(r.data[r.offset : r.offset+jvmSizeOfUint16]), nil
}
