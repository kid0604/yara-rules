rule EquationGroup_Toolset_Apr17_DoubleFeatureDll_dll_3
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		date = "2017-04-15"
		hash1 = "515374423b8b132258bd91acf6f29168dcc267a3f45ecb9d1fe18ee3a253195b"
		os = "windows"
		filetype = "executable"

	strings:
		$a = { f4 65 c6 45 f5 6c c6 45 f6 33 c6 45 f7 32 c6 45 }
		$b = { 36 c6 45 e6 34 c6 45 e7 50 c6 45 e8 72 c6 45 e9 }
		$c = { c6 45 e8 65 c6 45 e9 70 c6 45 ea 74 c6 45 eb 5f }

	condition:
		( uint16(0)==0x5a4d and filesize <1000KB and all of them )
}
