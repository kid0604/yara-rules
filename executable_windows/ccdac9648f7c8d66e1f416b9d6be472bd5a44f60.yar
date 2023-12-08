rule CobaltStrike_Resources_Beacon_Dll_v3_5_hf1_and_3_5_1
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Versions 3.5-hf1 and 3.5.1 (3.5.x)"
		hash = "c78e70cd74f4acda7d1d0bd85854ccacec79983565425e98c16a9871f1950525"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		os = "windows"
		filetype = "executable"

	strings:
		$version_sig = { 48 57 8B F1 83 F8 43 0F 87 07 03 00 00 FF 24 }
		$decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}
