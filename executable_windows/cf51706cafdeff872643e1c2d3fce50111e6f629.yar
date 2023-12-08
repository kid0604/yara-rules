import "pe"

rule HACKSTOPv110v111
{
	meta:
		author = "malware-lu"
		description = "Detects HACKSTOP version 1.10 and 1.11"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { B4 30 CD 21 86 E0 3D [2] 73 ?? B4 2F CD 21 B0 ?? B4 4C CD 21 50 B8 [2] 58 EB }

	condition:
		$a0 at pe.entry_point
}
