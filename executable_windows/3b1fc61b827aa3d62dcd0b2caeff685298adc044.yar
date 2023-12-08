import "pe"

rule EXEPackerv70byTurboPowerSoftware
{
	meta:
		author = "malware-lu"
		description = "Detects the EXEPackerv70 by TurboPower Software"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 1E 06 8C C3 83 [2] 2E [4] B9 [2] 8C C8 8E D8 8B F1 4E 8B FE }

	condition:
		$a0 at pe.entry_point
}
