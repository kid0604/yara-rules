rule CobaltStrike_Resources_Beacon_Dll_v1_48
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Version 1.48"
		hash = "dd4e445572cd5e32d7e9cc121e8de337e6f19ff07547e3f2c6b7fce7eafd15e4"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		os = "windows"
		filetype = "executable"

	strings:
		$version_sig = { 48 57 8B F1 8B DA 83 F8 17 77 12 FF 24 }
		$decode = { B1 ?? 30 88 [4] 40 3D A8 01 00 00 7C F2 }

	condition:
		all of them
}
