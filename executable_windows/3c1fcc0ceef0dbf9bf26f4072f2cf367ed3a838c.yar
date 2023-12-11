rule APT_MAL_NK_Lazarus_VHD_Ransomware_Oct20_2
{
	meta:
		description = "Detects Lazarus VHD Ransomware"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/lazarus-on-the-hunt-for-big-game/97757/"
		date = "2020-10-05"
		hash1 = "097ca829e051a4877bca093cee340180ff5f13a9c266ad4141b0be82aae1a39b"
		hash2 = "73a10be31832c9f1cbbd798590411009da0881592a90feb472e80025dfb0ea79"
		os = "windows"
		filetype = "executable"

	strings:
		$op1 = { f9 36 88 08 8d ad fc ff ff ff 66 ff c1 e9 72 86 }
		$op2 = { c6 c4 58 0f a4 c8 12 8d ad ff ff ff ff 0f b6 44 }
		$op3 = { 88 02 66 c1 f0 54 8d bf fc ff ff ff 0f ba e0 19 }

	condition:
		uint16(0)==0x5a4d and filesize <9000KB and all of them
}
