rule CobaltStrike_Resources_Beacon_x64_v3_2
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.2"
		hash = "5993a027f301f37f3236551e6ded520e96872723a91042bfc54775dcb34c94a1"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		os = "windows"
		filetype = "executable"

	strings:
		$version_sig = { 4C 8D 05 9F F8 FF FF 8B D3 48 8B CF E8 05 1A 00 00
                     EB 0A 8B D3 48 8B CF E8 41 21 00 00 48 8B 5C 24 30
                     48 83 C4 20 }
		$decoder = { 80 31 ?? FF C2 48 FF C1 48 63 C2 48 3D 10 06 00 00 }

	condition:
		all of them
}
