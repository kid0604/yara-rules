import "pe"

rule LamerStopv10ccStefanEsser
{
	meta:
		author = "malware-lu"
		description = "Detects the LamerStopv10ccStefanEsser malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 [2] 05 [2] CD 21 33 C0 8E C0 26 [3] 2E [3] 26 [3] 2E [3] BA [2] FA }

	condition:
		$a0 at pe.entry_point
}
