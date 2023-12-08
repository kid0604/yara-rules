import "pe"

rule Upackv010v012BetaDwing
{
	meta:
		author = "malware-lu"
		description = "Detects the Upack v010-v012 Beta Dwing malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { BE 48 01 [5] 95 A5 33 C0 }

	condition:
		$a0 at pe.entry_point
}
