rule CobaltStrike_Resources_Beacon_Dll_v2_0_49
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Version 2.0.49"
		hash = "ed08c1a21906e313f619adaa0a6e5eb8120cddd17d0084a30ada306f2aca3a4e"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		os = "windows"
		filetype = "executable"

	strings:
		$version_sig = { 83 F8 22 0F 87 96 01 00 00 FF 24 }
		$decoder = { B1 ?? EB 03 8D 49 00 30 88 [4] 40 3D 30 05 00 00 72 F2  }

	condition:
		all of them
}
