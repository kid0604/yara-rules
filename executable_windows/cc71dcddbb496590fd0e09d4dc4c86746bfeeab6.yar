import "pe"

rule HACKSTOPv110p1
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of HACKSTOPv110p1 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { B4 30 CD 21 86 E0 3D 00 03 73 ?? B4 2F CD 21 B4 2A CD 21 B4 2C CD 21 B0 FF B4 4C CD 21 50 B8 [2] 58 EB }

	condition:
		$a0 at pe.entry_point
}
