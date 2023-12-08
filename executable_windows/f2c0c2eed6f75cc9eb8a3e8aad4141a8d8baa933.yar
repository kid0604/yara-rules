rule CobaltStrike_Resources_Beacon_Dll_v1_46
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Version 1.46"
		hash = "44e34f4024878024d4804246f57a2b819020c88ba7de160415be38cd6b5e2f76"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		os = "windows"
		filetype = "executable"

	strings:
		$version_sig = { 8B F2 83 F9 0C 0F 87 8E 00 00 00 FF 24 }
		$decode = { B1 ?? 30 88 [4] 40 3D A8 01 00 00 7C F2 }

	condition:
		all of them
}
