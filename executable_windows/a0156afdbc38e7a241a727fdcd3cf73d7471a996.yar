rule CobaltStrike_Resources_Beacon_Dll_v3_8
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Versions 3.8"
		hash = "67b6557f614af118a4c409c992c0d9a0cc800025f77861ecf1f3bbc7c293d603"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		os = "windows"
		filetype = "executable"

	strings:
		$version_sig = { 48 57 8B F9 83 F8 4B 0F 87 5D 03 00 00 FF 24 }
		$decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }
		$xmrig_srcpath = "C:/Users/SKOL-NOTE/Desktop/Loader/script.go"
		$c2_1 = "ns7.softline.top" xor
		$c2_2 = "ns8.softline.top" xor
		$c2_3 = "ns9.softline.top" xor

	condition:
		$version_sig and $decoder and (2 of ($c2_*) or $xmrig_srcpath)
}
