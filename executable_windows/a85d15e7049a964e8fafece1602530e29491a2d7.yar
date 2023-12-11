import "pe"

rule VcAsmProtectorVcAsm
{
	meta:
		author = "malware-lu"
		description = "Detects VcAsm Protector VcAsm malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 6A FF 68 [4] 68 [4] 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 C3 }

	condition:
		$a0 at pe.entry_point
}
