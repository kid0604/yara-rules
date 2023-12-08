rule EquationGroup_cursesleepy_mswin32_v_1_0_0
{
	meta:
		description = "Equation Group hack tool set"
		author = "Florian Roth"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		date = "2017-04-09"
		hash1 = "6293439b4b49e94f923c76e302f5fc437023c91e063e67877d22333f05a24352"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "A}%j,R" fullword ascii
		$op1 = { a1 e0 43 41 00 8b 0d 34 44 41 00 6b c0 }
		$op2 = { 33 C0 F3 A6 74 14 8B 5D 08 8B 4B 34 50 }

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and 2 of them )
}
