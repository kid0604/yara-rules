import "pe"

rule Upackv032BetaDwing
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of Upack v0.32 Beta Dwing packer"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { BE 88 01 [2] AD 50 [2] AD 91 F3 A5 }
		$a1 = { BE 88 01 [2] AD 50 ?? AD 91 ?? F3 A5 }

	condition:
		$a0 or $a1
}
