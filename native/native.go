package native

import (
	"fmt"
	"strings"
	"unsafe"
)

// Slice is the runtime representation of a slice.
// It cannot be used safely or portably and its representation may change in a later release.
type Slice struct {
	Data unsafe.Pointer
	Len  int
	Cap  int
}

// String is the runtime representation of a string.
// It cannot be used safely or portably and its representation may change in a later release.
type String struct {
	Data unsafe.Pointer
	Len  int
}
type NeedName struct {
	FuncAddress uintptr
	FuncName    string
}
type UNICODE_STRING struct {
	Length        uint16
	MaximumLength uint16
	Buffer        uintptr
}
type LIST_ENTRY struct {
	Flink uintptr
	Blink uintptr
}
type LDR_DATA_TABLE_ENTRY struct {
	InOrderLinks               LIST_ENTRY
	InMemoryOrderLinks         LIST_ENTRY
	InInitializationOrderLinks LIST_ENTRY
	DllBase                    uintptr
	Entrypoint                 uintptr
	SizeOfImage                uint32
	FullDllName                UNICODE_STRING
	BaseDllName                UNICODE_STRING
}

func GetPEB() uintptr
func Syscall(callid uint16, callfunc uintptr, argh ...uintptr) uint32
func PtrToUInt16(ptr uintptr) uint16 {
	p := unsafe.Pointer(ptr)
	return *(*uint16)(p)
}

func PtrToUInt32(ptr uintptr) uint32 {
	p := unsafe.Pointer(ptr)
	return *(*uint32)(p)
}

func PtrToUInt64(ptr uintptr) uint64 {
	p := unsafe.Pointer(ptr)
	return *(*uint64)(p)
}

func BytePtrToStringAnsi(p *byte) string {
	if p == nil {
		return ""
	}
	if *p == 0 {
		return ""
	}

	// Find NUL terminator.
	n := 0
	for ptr := unsafe.Pointer(p); *(*byte)(ptr) != 0; n++ {
		ptr = unsafe.Pointer(uintptr(ptr) + 1)
	}

	var s []byte
	h := (*Slice)(unsafe.Pointer(&s))
	h.Data = unsafe.Pointer(p)
	h.Len = n
	h.Cap = n

	return string(s)
}
func BytePtrToStringUni(p *byte) string {
	if p == nil {
		return ""
	}
	if *p == 0 {
		return ""
	}

	// Find NUL terminator.
	n := 0
	nullCounter := 0
	ptr := unsafe.Pointer(p)
	for {
		if *(*byte)(ptr) == 0 {
			nullCounter++
		} else {
			nullCounter = 0
		}
		ptr = unsafe.Pointer(uintptr(ptr) + 1)
		if nullCounter > 1 {
			break
		}
		n++
	}

	var s []byte
	h := (*Slice)(unsafe.Pointer(&s))
	h.Data = unsafe.Pointer(p)
	h.Len = n
	h.Cap = n

	return strings.Replace(string(s), "\x00", "", -1)
}
func syscallfunc()
func IndirectSyscall(api string, NtFunctionsOrdered []NeedName, args ...uintptr) uint32 {
	var id uint16
	var apiLoc uintptr
	for i := 0; i < len(NtFunctionsOrdered); i++ {
		if NtFunctionsOrdered[i].FuncName == api {
			id = uint16(i)
		}

		if NtFunctionsOrdered[i].FuncName == "NtDrawText" {
			apiLoc = NtFunctionsOrdered[i].FuncAddress
		}

	}

	r0 := Syscall(id, uintptr(unsafe.Add(unsafe.Pointer(apiLoc), 18)), args...)

	fmt.Printf("NTSTATUS of %s is %#x\n", api, r0)
	return r0
}
