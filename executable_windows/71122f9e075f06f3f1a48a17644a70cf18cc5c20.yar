rule CobaltStrike_Sleeve_Beacon_x64_v4_1_and_v_4_2
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 4.1 and 4.2"
		hash = "29ec171300e8d2dad2e1ca2b77912caf0d5f9d1b633a81bb6534acb20a1574b2"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		os = "windows"
		filetype = "executable"

	strings:
		$version_sig = { 83 F9 34 0F 87 8E 03 00 00 0F 84 7A 03 00 00 83 F9 1C 0F 87 E6 01 00 00
                     0F 84 D7 01 00 00 83 F9 0E 0F 87 E9 00 00 00 0F 84 CE 00 00 00 FF C9
                     0F 84 B8 00 00 00 83 E9 02 0F 84 9F 00 00 00 FF C9 }
		$decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}
