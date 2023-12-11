import "pe"

rule AntiVirusVaccinev103
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of AntiVirusVaccinev103 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { FA 33 DB B9 [2] 0E 1F 33 F6 FC AD 35 [2] 03 D8 E2 }

	condition:
		$a0 at pe.entry_point
}
