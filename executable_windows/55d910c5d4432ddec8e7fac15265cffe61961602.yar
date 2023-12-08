import "pe"

rule GameGuardv20065xxexesignbyhot_UNP
{
	meta:
		author = "malware-lu"
		description = "Detects GameGuardv20065xxexesignbyhot_UNP malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 31 FF 74 06 61 E9 4A 4D 50 30 5A BA 7D 00 00 00 80 7C 24 08 01 E9 00 00 00 00 60 BE 00 }

	condition:
		$a0 at pe.entry_point
}
