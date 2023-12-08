import "pe"

rule VcasmProtector10_alt_1
{
	meta:
		author = "malware-lu"
		description = "Yara rule for detecting VcasmProtector10_alt_1 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 6A FF 68 [3] 00 68 [3] 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 C3 FF 35 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 C3 FF 35 E8 07 00 00 00 C7 83 83 C0 13 EB 0B 58 EB 02 CD 20 83 }

	condition:
		$a0 at pe.entry_point
}
