import "pe"

rule INDICATOR_EXE_Packed_LLVMLoader
{
	meta:
		author = "ditekSHen"
		description = "Detects LLVM obfuscator/loader"
		clamav_sig = "INDICATOR.Packed.LLVMLoader"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "exeLoaderDll_LLVMO.dll" fullword ascii
		$b = { 64 6c 6c 00 53 74 61 72 74 46 75 6e 63 00 00 00
               ?? ?? 00 00 00 00 00 00 00 00 00 ?? 96 01 00 00
               ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00
               00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 00
               00 00 00 00 00 00 00 00 00 00 00 ?? ?? 45 78 69
               74 50 72 6f 63 65 73 73 00 4b 45 52 4e 45 4c 33
               32 2e 64 6c 6c 00 00 00 00 00 00 }

	condition:
		( uint16(0)==0x5a4d or uint16(0)==0x0158) and ((pe.exports("StartFunc") and 1 of ($s*)) or all of ($s*) or ($b))
}
