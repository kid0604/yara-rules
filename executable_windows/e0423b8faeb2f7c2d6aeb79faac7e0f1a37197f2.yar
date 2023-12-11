rule EquationGroup_Toolset_Apr17_Esteemaudit_2_1_0
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		date = "2017-04-15"
		hash1 = "61f98b12c52739647326e219a1cf99b5440ca56db3b6177ea9db4e3b853c6ea6"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "[+] Connected to target %s:%d" fullword ascii
		$x2 = "[-] build_exploit_run_x64():" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and 1 of them )
}
