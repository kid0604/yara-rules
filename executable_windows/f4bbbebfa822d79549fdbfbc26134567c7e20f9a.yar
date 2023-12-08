rule EquationGroup_Toolset_Apr17_Eclipsedwingtouch_1_0_4
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		date = "2017-04-15"
		hash1 = "46da99d80fc3eae5d1d5ab2da02ed7e61416e1eafeb23f37b180c46e9eff8a1c"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "[-] The target is NOT vulnerable" fullword ascii
		$x2 = "[+] The target IS VULNERABLE" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <50KB and 1 of them )
}
