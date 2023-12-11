import "pe"

rule InstallStub32bit
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of InstallStub 32-bit malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 81 EC 14 ?? 00 00 53 56 57 6A 00 FF 15 [4] 68 [4] FF 15 [4] 85 C0 74 29 }

	condition:
		$a0 at pe.entry_point
}
