rule MAL_OBFUSC_Unknown_Jan22_1
{
	meta:
		description = "Detects samples similar to reversed stage3 found in Ukrainian wiper incident named WhisperGate"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/juanandres_gs/status/1482827018404257792"
		date = "2022-01-16"
		hash1 = "9ef7dbd3da51332a78eff19146d21c82957821e464e8133e9594a07d716d892d"
		os = "windows"
		filetype = "executable"

	strings:
		$xc1 = { 37 00 63 00 38 00 63 00 62 00 35 00 35 00 39 00
               38 00 65 00 37 00 32 00 34 00 64 00 33 00 34 00
               33 00 38 00 34 00 63 00 63 00 65 00 37 00 34 00
               30 00 32 00 62 00 31 00 31 00 66 00 30 00 65 }
		$xc2 = { 4D 61 69 6E 00 43 6C 61 73 73 4C 69 62 72 61 72
               79 31 00 70 63 31 65 }
		$s1 = ".dll" wide
		$s2 = "%&%,%s%" ascii fullword
		$op1 = { a2 87 fa b1 44 a5 f5 12 da a7 49 11 5c 8c 26 d4 75 }
		$op2 = { d7 af 52 38 c7 47 95 c8 0e 88 f3 d5 0b }
		$op3 = { 6c 05 df d6 b8 ac 11 f2 67 16 cb b7 34 4d b6 91 }

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and (1 of ($x*) or 3 of them )
}
