rule EquationGroup_Toolset_Apr17_Easybee_1_0_1
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		date = "2017-04-15"
		hash1 = "59c17d6cb564edd32c770cd56b5026e4797cf9169ff549735021053268b31611"
		os = "windows"
		filetype = "script"

	strings:
		$x1 = "@@for /f \"delims=\" %%i in ('findstr /smc:\"%s\" *.msg') do if not \"%%MsgFile1%%\"==\"%%i\" del /f \"%%i\"" fullword ascii
		$x2 = "Logging out of WebAdmin (as target account)" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and 1 of them )
}
