rule Delphi_Copy
{
	meta:
		author = "_pusher_"
		description = "Look for Copy function"
		date = "2016-06"
		version = "0.1"
		os = "windows"
		filetype = "executable"

	strings:
		$c0 = { 53 85 C0 74 2D 8B 58 FC 85 DB 74 26 4A 7C 1B 39 DA 7D 1F 29 D3 85 C9 7C 19 39 D9 7F 11 01 C2 8B 44 24 08 E8 ?? ?? ?? ?? EB 11 31 D2 EB E5 89 D9 EB EB 8B 44 24 08 E8 ?? ?? ?? ?? 5B C2 04 00 }
		$c1 = { 53 48 83 EC 20 48 89 CB 44 89 C0 48 33 C9 48 85 D2 74 03 8B 4A FC 83 F8 01 7D 05 48 33 C0 EB 09 83 E8 01 3B C1 7E 02 89 C8 45 85 C9 7D 05 48 33 C9 EB 0A 2B C8 41 3B C9 7E 03 44 89 C9 49 89 D8 48 63 C0 48 8D 14 42 89 C8 4C 89 C1 41 89 C0 E8 ?? ?? ?? ?? 48 89 D8 48 83 C4 20 5B C3 }

	condition:
		any of them
}
