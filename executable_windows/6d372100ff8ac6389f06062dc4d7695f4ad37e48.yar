import "pe"

rule Upackv033v034BetaDwing
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of Upack v0.33 or v0.34 Beta Dwing malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 59 F3 A5 83 C8 FF 8B DF AB 40 AB 40 }

	condition:
		$a0 at pe.entry_point
}
