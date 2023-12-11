rule CobaltStrike_Resources_Beacon_x64_v3_12
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.12"
		hash = "8a28b7a7e32ace2c52c582d0076939d4f10f41f4e5fa82551e7cc8bdbcd77ebc"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		os = "windows"
		filetype = "executable"

	strings:
		$version_sig = { 8B D3 48 8B CF E8 F8 2E 00 00 EB 16 8B D3 48 8B CF
                     E8 00 5C 00 00 EB 0A 8B D3 48 8B CF E8 64 4F 00 00 }
		$decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}
