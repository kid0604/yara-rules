rule CobaltStrike_Sleeve_Beacon_x64_v4_3
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.x64.dll Version 4.3"
		hash = "3ac9c3525caa29981775bddec43d686c0e855271f23731c376ba48761c27fa3d"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		os = "windows"
		filetype = "executable"

	strings:
		$version_sig = { 8B D0 49 8B CA 48 83 C4 28 E9 D3 88 FF FF
                     4C 8D 05 84 6E FF FF 8B D0 49 8B CA 48 83 C4 28 }
		$decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}
