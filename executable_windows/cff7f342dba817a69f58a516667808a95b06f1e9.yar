import "pe"

rule PECompact2xxBitSumTechnologies
{
	meta:
		author = "malware-lu"
		description = "Yara rule for detecting PECompact 2.xx BitSum Technologies"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { B8 [4] 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 6F 6D 70 61 63 74 32 00 }

	condition:
		$a0 at pe.entry_point
}
