rule EquationGroup_Toolset_Apr17__vtuner_vtuner_1
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		date = "2017-04-15"
		super_rule = 1
		hash1 = "3e6bec0679c1d8800b181f3228669704adb2e9cbf24679f4a1958e4cdd0e1431"
		hash2 = "b0d2ebf455092f9d1f8e2997237b292856e9abbccfbbebe5d06b382257942e0e"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Unable to get -w hash.  %x" fullword wide
		$s2 = "!\"invalid instruction mnemonic constant Id3vil\"" fullword wide
		$s4 = "Unable to set -w provider. %x" fullword wide
		$op0 = { 2b c7 50 e8 3a 8c ff ff ff b6 c0 }
		$op2 = { a1 8c 62 47 00 81 65 e0 ff ff ff 7f 03 d8 8b c1 }

	condition:
		( uint16(0)==0x5a4d and filesize <2000KB and 2 of them )
}
