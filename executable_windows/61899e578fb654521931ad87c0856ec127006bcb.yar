rule CobaltStrike_Resources_Beacon_Dll_v3_3
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Versions 3.3"
		hash = "158dba14099f847816e2fc22f254c60e09ac999b6c6e2ba6f90c6dd6d937bc42"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		os = "windows"
		filetype = "executable"

	strings:
		$version_sig = { 48 57 8B F1 83 F8 41 0F 87 F0 02 00 00 FF 24 }
		$decoder = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }

	condition:
		all of them
}
