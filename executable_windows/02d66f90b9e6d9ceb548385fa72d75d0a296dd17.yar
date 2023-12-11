rule CobaltStrike_Resources_Beacon_x64_v3_4
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.4"
		hash = "5a4d48c2eda8cda79dc130f8306699c8203e026533ce5691bf90363473733bf0"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		os = "windows"
		filetype = "executable"

	strings:
		$version_sig = { 8B D3 48 8B CF E8 56 6F 00 00 E9 17 FB FF FF
                     41 B8 01 00 00 00 8B D3 48 8B CF E8 41 4D 00 00
                     48 8B 5C 24 30 48 83 C4 20 }
		$decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}
