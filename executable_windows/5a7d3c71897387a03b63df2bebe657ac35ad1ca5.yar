rule EquationGroup_charm_saver_win2k_v_2_0_0
{
	meta:
		description = "Equation Group hack tool set"
		author = "Florian Roth"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		date = "2017-04-09"
		hash1 = "0f7936a37482532a8ba5df4112643ed7579dd0e59181bfca9c641b9ba0a9912f"
		os = "windows"
		filetype = "executable"

	strings:
		$s2 = "0123456789abcdefABCEDF:" fullword ascii
		$op0 = { b8 ff ff ff ff 7f 65 eb 30 8b 55 0c 89 d7 0f b6 }
		$op2 = { ba ff ff ff ff 83 c4 6c 89 d0 5b 5e 5f 5d c3 90 }

	condition:
		( uint16(0)==0x5a4d and filesize <400KB and all of them )
}
