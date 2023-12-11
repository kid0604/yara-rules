rule CobaltStrike_Sleeve_Beacon_Dll_v4_0_suspected
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.dll Versions 4.0 (suspected, not confirmed)"
		hash = "e2b2b72454776531bbc6a4a5dd579404250901557f887a6bccaee287ac71b248"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		os = "windows"
		filetype = "executable"

	strings:
		$version_sig = { 51 4A 56 57 83 FA 62 0F 87 8F 03 00 00 FF 24 95 56 7B 00 10 }
		$decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}
