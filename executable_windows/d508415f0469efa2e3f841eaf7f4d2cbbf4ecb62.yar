rule ModiLoader_alt_2
{
	meta:
		author = "kevoreilly"
		description = "ModiLoader detonation shim"
		cape_options = "exclude-apis=NtAllocateVirtualMemory:NtProtectVirtualMemory"
		hash = "1f0cbf841a6bc18d632e0bc3c591266e77c99a7717a15fc4b84d3e936605761f"
		os = "windows"
		filetype = "executable"

	strings:
		$epilog1 = {81 C2 A1 03 00 00 87 D1 29 D3 33 C0 5A 59 59 64 89 10 68}
		$epilog2 = {6A 00 6A 01 8B 45 ?? 50 FF 55 ?? 33 C0 5A 59 59 64 89 10 68}

	condition:
		uint16(0)==0x5a4d and all of them
}
