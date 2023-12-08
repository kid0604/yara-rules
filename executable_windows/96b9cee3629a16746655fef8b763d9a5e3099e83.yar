import "pe"

rule Upackv022v023BetaDwing
{
	meta:
		author = "malware-lu"
		description = "Detects the Upack v022/v023 Beta Dwing malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 6A 07 BE 88 01 40 00 AD 8B F8 59 95 F3 A5 }

	condition:
		$a0 at pe.entry_point
}
