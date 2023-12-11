rule EquationGroup_Toolset_Apr17_DoubleFeatureDll_dll_2
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		date = "2017-04-15"
		hash1 = "f265defd87094c95c7d3ddf009d115207cd9d4007cf98629e814eda8798906af"
		hash2 = "8d62ca9e6d89f2b835d07deb5e684a576607e4fe3740f77c0570d7b16ebc2985"
		hash3 = "634a80e37e4b32706ad1ea4a2ff414473618a8c42a369880db7cc127c0eb705e"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = ".dllfD" fullword ascii
		$s2 = "Khsppxu" fullword ascii
		$s3 = "D$8.exe" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <1000KB and 2 of them )
}
