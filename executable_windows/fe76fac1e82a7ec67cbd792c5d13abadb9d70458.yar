import "pe"

rule PEDiminisherv01
{
	meta:
		author = "malware-lu"
		description = "Yara rule to detect PEDiminisher malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 53 51 52 56 57 55 E8 00 00 00 00 5D 8B D5 81 ED A2 30 40 00 2B 95 91 33 40 00 81 EA 0B 00 00 00 89 95 9A 33 40 00 80 BD 99 33 40 00 00 74 }
		$a1 = { 5D 8B D5 81 ED A2 30 40 ?? 2B 95 91 33 40 ?? 81 EA 0B [3] 89 95 9A 33 40 ?? 80 BD 99 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}
