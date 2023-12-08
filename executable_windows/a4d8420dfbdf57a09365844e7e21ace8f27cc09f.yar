import "pe"

rule VIRUSIWormHybris_alt_1
{
	meta:
		author = "malware-lu"
		description = "Detects the VIRUSIWormHybris_alt_1 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 16 A8 54 [2] 47 41 42 4C 4B 43 47 43 [6] 52 49 53 ?? FC 68 4C 70 40 ?? FF 15 }

	condition:
		$a0
}
