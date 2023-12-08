rule CobaltStrike_Resources_Beacon_Dll_v2_4
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Versions 2.4"
		hash = "78c6f3f2b80e6140c4038e9c2bcd523a1b205d27187e37dc039ede4cf560beed"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		os = "windows"
		filetype = "executable"

	strings:
		$version_sig = { 4A 56 57 83 FA 2F 0F 87 F9 01 00 00 FF 24 }
		$decoder = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }

	condition:
		all of them
}
