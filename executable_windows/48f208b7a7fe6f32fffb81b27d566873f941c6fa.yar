import "pe"

rule FreeBASIC016b
{
	meta:
		author = "malware-lu"
		description = "Detects FreeBASIC compiled executables based on specific byte sequences in the entry point"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 89 E5 83 EC 08 C7 04 24 01 00 00 00 FF 15 [3] 00 E8 88 FF FF FF 89 EC 31 C0 5D C3 89 F6 55 89 E5 83 EC 08 C7 04 24 02 00 00 00 FF 15 [3] 00 E8 68 FF FF FF 89 EC 31 C0 5D C3 89 F6 55 89 E5 83 EC 08 8B 45 08 89 04 24 FF 15 [3] 00 89 EC 5D C3 8D 76 00 8D BC 27 00 00 00 00 55 89 E5 83 EC 08 8B 45 08 89 04 24 FF 15 [3] 00 89 EC 5D C3 90 90 90 90 90 90 90 90 90 90 }

	condition:
		$a0 at pe.entry_point
}
