rule EquationGroup_Toolset_Apr17_ntfltmgr
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		date = "2017-04-15"
		hash1 = "3df61b8ef42a995b8f15a0d38bc51f2f08f8d9a2afa1afc94c6f80671cf4a124"
		hash2 = "f7a886ee10ee6f9c6be48c20f370514be62a3fd2da828b0dff44ff3d485ff5c5"
		hash3 = "980954a2440122da5840b31af7e032e8a25b0ce43e071ceb023cca21cedb2c43"
		os = "windows"
		filetype = "executable"

	strings:
		$s3 = "wCw3wDwAw2wNw@wEwZw2wDwEwBwZwFwFw4w2wZw5w1w4wFwZwGwOwGwGwEw5w2wFwGwDwFwOw" fullword ascii
		$s6 = "w+w;w2w0w6w4w.w(wRw" fullword ascii
		$op1 = { 80 f7 ff ff 49 89 84 34 18 02 00 00 41 83 a4 34 }
		$op2 = { ff 15 0b 34 00 00 eb 92 }
		$op3 = { 4d 8d b4 34 08 02 00 00 4d 85 f6 0f 84 ae }
		$op4 = { 8b ca 2b ce 8d 34 01 0f b7 3e 66 3b 7d f0 89 75 }
		$op5 = { 8a 40 01 00 c7 47 70 }
		$op6 = { e9 3c ff ff ff 6a ff 8d 45 f0 50 e8 27 11 00 00 }
		$op7 = { 8b 45 08 53 57 8b 7d 0c c7 40 34 }

	condition:
		( uint16(0)==0x5a4d and filesize <100KB and 4 of them )
}
