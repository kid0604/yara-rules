rule CobaltStrike_Resources_Beacon_Dll_v1_47
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Version 1.47"
		hash = "8ff6dc80581804391183303bb39fca2a5aba5fe13d81886ab21dbd183d536c8d"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		os = "windows"
		filetype = "executable"

	strings:
		$version_sig = { 83 F8 12 77 10 FF 24 }
		$decode = { B1 ?? 30 88 [4] 40 3D A8 01 00 00 }

	condition:
		all of them
}
