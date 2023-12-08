import "pe"

rule Upackv02BetaDwing
{
	meta:
		author = "malware-lu"
		description = "Detects the Upackv02BetaDwing malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { BE 88 01 [2] AD 8B F8 95 A5 33 C0 33 }

	condition:
		$a0 at pe.entry_point
}
