import "pe"

rule PEDiminisherV01Teraphy
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of PEDiminisherV01Teraphy malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 53 51 52 56 57 55 E8 00 00 00 00 }

	condition:
		$a0 at pe.entry_point
}
