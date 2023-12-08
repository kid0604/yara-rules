rule MAL_Loader_TurtleLoader_Nov23
{
	meta:
		description = "Detects Tutle loader used in attacks against SysAid CVE-2023-47246"
		author = "Florian Roth"
		reference = "https://www.sysaid.com/blog/service-desk/on-premise-software-security-vulnerability-notification"
		date = "2023-11-09"
		score = 85
		hash1 = "b5acf14cdac40be590318dee95425d0746e85b1b7b1cbd14da66f21f2522bf4d"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "No key in args!" ascii fullword
		$s2 = "Bad data file!" ascii fullword
		$s3 = "Data file loaded. Running..." ascii
		$op1 = { 48 8d 55 c8 4c 8d 3d ac 8f 00 00 45 33 c9 45 33 d2 4d 8b e7 44 21 0a 45 33 db 4c 8d 3d 16 ec ff ff }
		$op2 = { 48 d3 e8 0f b6 c8 49 03 cb 49 81 c3 00 01 00 00 45 33 8c 8f a0 e4 00 00 41 83 fa 04 7c c7 41 ff c0 }
		$op3 = { 48 83 c1 04 48 ff ca 89 41 1c 75 ef 03 f6 48 83 c3 20 48 ff cd 0f 85 77 ff ff ff }

	condition:
		uint16(0)==0x5a4d and filesize <200KB and 3 of them
}
