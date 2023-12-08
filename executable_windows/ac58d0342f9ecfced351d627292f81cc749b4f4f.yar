import "pe"

rule Upackv021BetaDwing
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of Upack v0.21 Beta Dwing malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { BE 88 01 [2] AD 8B F8 [4] 33 }

	condition:
		$a0 at pe.entry_point
}
