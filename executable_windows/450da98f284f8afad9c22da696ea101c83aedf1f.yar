import "pe"

rule VcAsmProtectorV10XVcAsm
{
	meta:
		author = "malware-lu"
		description = "Detects VcAsm Protector v1.0X VcAsm"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 6A FF 68 [4] 68 [4] 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00 }

	condition:
		$a0 at pe.entry_point
}
