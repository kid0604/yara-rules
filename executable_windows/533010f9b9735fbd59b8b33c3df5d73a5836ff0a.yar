rule FGint_FGIntModExp
{
	meta:
		author = "_pusher_"
		date = "2015-05"
		description = "FGint FGIntModExp"
		os = "windows"
		filetype = "executable"

	strings:
		$c0 = { 55 8B EC 83 C4 E8 53 56 57 33 DB 89 5D ?? 8B F1 89 55 ?? 8B D8 8B 7D 08 8D 45 F4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 EC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8B 46 04 8B 40 04 83 E0 01 83 F8 01 75 0F 57 8B CE 8B 55 ?? 8B C3 E8 ?? ?? ?? ?? EB ?? 8D 55 ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B D7 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 55 F4 8B C3 E8 ?? ?? ?? ?? 8B 45 }

	condition:
		$c0
}
