rule EquationGroup_Toolset_Apr17_Eternalromance_alt_1
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		date = "2017-04-15"
		super_rule = 1
		hash1 = "f1ae9fdbb660aae3421fd3e5b626c1e537d8e9ee2f9cd6d56cb70b6878eaca5d"
		hash2 = "b99c3cc1acbb085c9a895a8c3510f6daaf31f0d2d9ccb8477c7fb7119376f57b"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "[-] Error: Exploit choice not supported for target OS!!" fullword ascii
		$x2 = "Error: Target machine out of NPP memory (VERY BAD!!) - Backdoor removed" fullword ascii
		$x3 = "[-] Error: Backdoor not present on target" fullword ascii
		$x4 = "***********    TARGET ARCHITECTURE IS X64    ************" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and 1 of them ) or 2 of them
}
