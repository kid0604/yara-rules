rule FGint_ConvertHexStringToBase256String
{
	meta:
		author = "_pusher_"
		date = "2015-06"
		version = "0.2"
		description = "FGint ConvertHexStringToBase256String"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$c0 = { 55 8B EC 83 C4 F0 53 56 33 C9 89 4D F0 89 55 F8 89 45 FC 8B 45 FC E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8B 45 F8 E8 ?? ?? ?? ?? 8B 45 FC E8 ?? ?? ?? ?? D1 F8 79 03 83 D0 00 85 C0 7E 5F 89 45 F4 BE 01 00 00 00 8B C6 03 C0 8B 55 FC 8A 54 02 FF 8B 4D FC 8A 44 01 FE 3C 3A 73 0A 8B D8 80 EB 30 C1 E3 04 EB 08 8B D8 80 EB 37 C1 E3 04 80 FA 3A 73 07 80 EA 30 0A DA EB 05 80 EA 37 0A DA 8D 45 F0 8B D3 }

	condition:
		$c0
}
