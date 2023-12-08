rule FGint_DSASign
{
	meta:
		author = "_pusher_"
		date = "2016-08"
		description = "FGint DSASign"
		version = "0.1"
		os = "windows"
		filetype = "executable"

	strings:
		$c0 = { 55 8B EC 83 C4 CC 53 56 57 89 4D FC 8B DA 8B F8 8B 75 14 8B 45 10 E8 ?? ?? ?? ?? 8D 45 F4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 EC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 DC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 D4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 CC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8D 45 F4 50 8B CF 8B D6 8B 45 FC E8 ?? ?? ?? ?? 8D 4D D4 8B D3 8D 45 F4 E8 ?? ?? ?? ?? 8D 45 F4 E8 ?? ?? ?? ?? 8D 4D F4 8B D3 8B C6 E8 ?? ?? ?? ?? 8D 55 EC 8B 45 10 E8 ?? ?? ?? ?? 8D 45 E4 50 8B CB 8D 55 D4 8B 45 18 E8 ?? ?? ?? ?? 8D 4D DC 8D 55 E4 8D 45 EC E8 ?? ?? ?? ?? 8D 45 EC E8 ?? ?? ?? ?? 8D 45 E4 E8 ?? ?? ?? ?? 8D 45 CC 50 8B CB 8D 55 DC 8D 45 F4 E8 ?? ?? ?? ?? 8D 45 F4 E8 ?? ?? ?? ?? 8D 45 DC E8 ?? ?? ?? ?? 8B 55 0C 8D 45 D4 E8 ?? ?? ?? ?? 8B 55 08 8D 45 CC E8 ?? ?? ?? ?? 8D 45 D4 E8 ?? ?? ?? ?? 8D 45 CC E8 ?? ?? ?? ?? 33 C0 5A 59 59 64 89 10 68 ?? ?? ?? ?? 8D 45 CC 8B 15 ?? ?? ?? ?? B9 06 00 00 00 E8 }

	condition:
		$c0
}
