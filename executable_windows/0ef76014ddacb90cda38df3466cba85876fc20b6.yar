rule CobaltStrike_Resources_Beacon_Dll_v3_7
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Versions 3.7"
		hash = "f18029e6b12158fb3993f4951dab2dc6e645bb805ae515d205a53a1ef41ca9b2"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		os = "windows"
		filetype = "executable"

	strings:
		$version_sig = { 48 57 8B F9 83 F8 49 0F 87 47 03 00 00 FF 24 }
		$decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}
