rule MAL_Backdoor_DLL_Nov23_1
{
	meta:
		author = "X__Junior"
		description = "Detects a backdoor DLL, that was seen being used by LockBit 3.0 affiliates exploiting CVE-2023-4966"
		reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-325a"
		date = "2023-11-23"
		hash1 = "cc21c77e1ee7e916c9c48194fad083b2d4b2023df703e544ffb2d6a0bfc90a63"
		hash2 = "0eb66eebb9b4d671f759fb2e8b239e8a6ab193a732da8583e6e8721a2670a96d"
		score = 80
		id = "3588d437-b561-5380-8dac-73a31f4cdb5a"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "ERROR GET INTERVAL" ascii
		$s2 = "OFF HIDDEN MODE" ascii
		$s3 = "commandMod:" ascii
		$s4 = "RESULT:" ascii
		$op1 = { C7 44 24 ?? 01 00 00 00 C7 84 24 ?? ?? ?? ?? FF FF FF FF 83 7C 24 ?? 00 74 ?? 83 BC 24 ?? ?? ?? ?? 00 74 ?? 4C 8D 8C 24 ?? ?? ?? ?? 41 B8 00 04 00 00 48 8D 94 24 ?? ?? ?? ?? 48 8B 4C 24 ?? FF 15 }
		$op2 = { 48 C7 44 24 ?? 00 00 00 00 C7 44 24 ?? 00 00 00 00 C7 44 24 ?? 03 00 00 00 48 8D 0D ?? ?? ?? ?? 48 89 4C 24 ?? 4C 8D 0D ?? ?? ?? ?? 44 0F B7 05 ?? ?? ?? ?? 48 8B D0 48 8B 4C 24 ?? FF 15 }

	condition:
		uint16(0)==0x5a4d and ( all of ($s*) or all of ($op*))
}
