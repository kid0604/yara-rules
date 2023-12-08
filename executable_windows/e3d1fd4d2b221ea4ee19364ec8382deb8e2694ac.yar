import "pe"

rule RJoiner12byVaska250320071658
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of RJoiner12byVaska250320071658 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 81 EC 0C 02 00 00 8D 85 F4 FD FF FF 56 50 68 04 01 00 00 FF 15 14 10 40 00 90 8D 85 F4 FD FF FF 50 FF 15 10 10 40 00 90 BE 00 20 40 00 90 83 3E FF 0F 84 84 00 00 00 53 57 33 FF 8D 46 }

	condition:
		$a0 at pe.entry_point
}
