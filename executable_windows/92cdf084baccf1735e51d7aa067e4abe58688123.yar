rule CobaltStrike_Resources_Beacon_x64_v3_11
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.11 (two subversions)"
		hash = "64007e104dddb6b5d5153399d850f1e1f1720d222bed19a26d0b1c500a675b1a"
		rs2 = "815f313e0835e7fdf4a6d93f2774cf642012fd21ce870c48ff489555012e0047"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		os = "windows"
		filetype = "executable"

	strings:
		$version_sig = { 48 83 EC 20 41 8B D8 48 8B FA 83 F9 2D 0F 87 B2 03 00 00
                     0F 84 90 03 00 00 83 F9 17 0F 87 F8 01 00 00
                     0F 84 DC 01 00 00 83 F9 0E 0F 87 F9 00 00 00
                     0F 84 DD 00 00 00 FF C9 0F 84 C0 00 00 00 83 E9 02
                     0F 84 A6 00 00 00 FF C9 }
		$decoder = {
      80 34 28 ?? 
      48 FF C0
      48 3D 00 10 00 00
      7C F1
    }

	condition:
		all of them
}
