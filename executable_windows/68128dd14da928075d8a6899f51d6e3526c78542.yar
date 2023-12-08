rule EquationGroup_Toolset_Apr17_msgkd_msslu64_msgki_mssld
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		date = "2017-04-15"
		hash1 = "9ab667b7b5b9adf4ff1d6db6f804824a22c7cc003eb4208d5b2f12809f5e69d0"
		hash2 = "320144a7842500a5b69ec16f81a9d1d4c8172bb92301afd07fb79bc0eca81557"
		hash3 = "c10f4b9abee0fde50fe7c21b9948a2532744a53bb4c578630a81d2911f6105a3"
		hash4 = "551174b9791fc5c1c6e379dac6110d0aba7277b450c2563e34581565609bc88e"
		hash5 = "8419866c9058d738ebc1a18567fef52a3f12c47270f2e003b3e1242d86d62a46"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "PQRAPAQSTUVWARASATAUAVAW" fullword ascii
		$s2 = "SQRUWVAWAVAUATASARAQAP" fullword ascii
		$s3 = "iijymqp" fullword ascii
		$s4 = "AWAVAUATASARAQI" fullword ascii
		$s5 = "WARASATAUAVM" fullword ascii
		$op1 = { 0c 80 30 02 48 83 c2 01 49 83 e9 01 75 e1 c3 cc }
		$op2 = { e8 10 66 0d 00 80 66 31 02 48 83 c2 02 49 83 e9 }
		$op3 = { 48 b8 53 a5 e1 41 d4 f1 07 00 48 33 }

	condition:
		( uint16(0)==0x5a4d and filesize <1000KB and 2 of ($s*) or all of ($op*))
}
