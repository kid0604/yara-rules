rule FGint_RsaSign
{
	meta:
		author = "Maxx"
		description = "FGint RsaSign"
		os = "windows"
		filetype = "executable"

	strings:
		$c0 = { 55 8B EC 83 C4 B8 53 56 57 89 4D F8 8B FA 89 45 FC 8B 75 0C 8B 5D 10 8B 45 FC E8 ?? ?? ?? ?? 8D 45 F0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 D8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 D0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 C8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 C0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 B8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8D 55 F0 }

	condition:
		$c0
}