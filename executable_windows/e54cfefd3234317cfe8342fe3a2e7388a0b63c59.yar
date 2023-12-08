import "pe"

rule Upackv032BetaPatchDwing
{
	meta:
		author = "malware-lu"
		description = "Detects the Upack v0.32 Beta Patch Dwing malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { BE 88 01 [2] AD 50 ?? AD 91 F3 A5 }

	condition:
		$a0
}
