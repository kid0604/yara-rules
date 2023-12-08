rule EquationGroup_Toolset_Apr17_Educatedscholar_1_0_0
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		date = "2017-04-15"
		hash1 = "4cce9e39c376f67c16df3bcd69efd9b7472c3b478e2e5ef347e1410f1105c38d"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "[+] Shellcode Callback %s:%d" fullword ascii
		$x2 = "[+] Exploiting Target" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <150KB and 1 of them )
}
