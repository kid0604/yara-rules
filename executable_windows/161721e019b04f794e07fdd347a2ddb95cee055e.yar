rule Delphi_StrToInt
{
	meta:
		author = "_pusher_"
		description = "Look for StrToInt function"
		date = "2016-06"
		version = "0.1"
		os = "windows"
		filetype = "executable"

	strings:
		$c0 = { 53 56 83 C4 F4 8B D8 8B D4 8B C3 E8 ?? ?? ?? ?? 8B F0 83 3C 24 00 74 19 89 5C 24 04 C6 44 24 08 0B 8D 54 24 04 A1 ?? ?? ?? ?? 33 C9 E8 ?? ?? ?? ?? 8B C6 83 C4 0C 5E 5B C3 }
		$c1 = { 55 56 53 48 83 EC 40 48 8B EC 48 89 CB 48 89 D9 48 8D 55 3C E8 ?? ?? ?? ?? 89 C6 83 7D 3C 00 74 1B 48 89 5D 20 C6 45 28 11 48 8B 0D ?? ?? ?? ?? 48 8D 55 20 4D 33 C0 E8 ?? ?? ?? ?? 89 F0 48 8D 65 40 5B 5E 5D C3 }

	condition:
		any of them
}
