rule CobaltStrike_Sleeve_Beacon_Dll_v4_7_suspected
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.dll Versions 4.7 (suspected, not confirmed)"
		hash = "da9e91b3d8df3d53425dd298778782be3bdcda40037bd5c92928395153160549"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		os = "windows"
		filetype = "executable"

	strings:
		$version_sig = { 53 56 48 57 8B F2 83 F8 67 0F 87 5E 03 00 00  }
		$decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}
