rule malware_windows_moonlightmaze_loki2crypto
{
	meta:
		description = "Rule to detect hardcoded DH modulus used in 1996/1997 Loki2 sourcecode; #ifdef STRONG_CRYPTO /* 384-bit strong prime */"
		reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
		author = "Costin Raiu, Kaspersky Lab"
		md5_1 = "19fbd8cbfb12482e8020a887d6427315"
		md5_2 = "ea06b213d5924de65407e8931b1e4326"
		md5_3 = "14ecd5e6fc8e501037b54ca263896a11"
		md5_4 = "e079ec947d3d4dacb21e993b760a65dc"
		md5_5 = "edf900cebb70c6d1fcab0234062bfc28"
		os = "windows"
		filetype = "executable"

	strings:
		$modulus = {DA E1 01 CD D8 C9 70 AF C2 E4 F2 7A 41 8B 43 39 52 9B 4B 4D E5 85 F8 49}

	condition:
		$modulus
}
