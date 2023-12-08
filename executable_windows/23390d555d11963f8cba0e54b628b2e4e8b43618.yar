rule BigDig_mpModExp
{
	meta:
		author = "Maxx"
		description = "BigDig mpModExp"
		os = "windows"
		filetype = "executable"

	strings:
		$c0 = { 56 8B 74 24 18 85 F6 75 05 83 C8 FF 5E C3 53 55 8B 6C 24 18 57 56 55 E8 ?? ?? ?? ?? 8B D8 83 C4 08 BF 00 00 00 80 8B 44 9D FC 85 C7 75 04 D1 EF 75 F8 83 FF 01 75 08 BF 00 00 00 80 4B EB 02 D1 EF 8B 44 24 18 56 8B 74 24 18 50 56 E8 ?? ?? ?? ?? 83 C4 0C 85 DB 74 4F 8D 6C 9D FC 8B 4C 24 24 8B 54 24 20 51 52 56 56 56 E8 ?? ?? ?? ?? 8B 45 00 83 C4 14 85 C7 74 19 8B 44 24 24 8B 4C 24 20 8B 54 24 18 50 51 52 56 56 E8 ?? ?? ?? ?? 83 C4 14 83 FF 01 75 0B 4B BF 00 00 00 80 83 ED 04 EB }

	condition:
		$c0
}
