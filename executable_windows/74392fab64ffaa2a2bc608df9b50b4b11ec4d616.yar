rule Enigma_Protected_Malware_May17_RhxFiles
{
	meta:
		description = "Auto-generated rule - file RhxFiles.dll"
		author = "Florian Roth (Nextron Systems) with the help of binar.ly"
		reference = "Internal Research"
		date = "2017-05-02"
		hash1 = "2187d6bd1794bf7b6199962d8a8677f19e4382a124c30933d01aba93cc1f0f15"
		os = "windows"
		filetype = "executable"

	strings:
		$op1 = { bd 9c 74 f6 7a 3a f7 94 c5 7d 7c 7c 7c 7e ae 73 }
		$op2 = { 82 62 6b 6b 6b 68 a5 ea aa 69 6b 6b 6b 3a 3b 94 }
		$op3 = { 7c 7c c5 7d 7c 7c 7c 7e ae 73 f9 79 7c 7c 7c f6 }

	condition:
		( uint16(0)==0x5a4d and filesize <4000KB and all of them )
}
