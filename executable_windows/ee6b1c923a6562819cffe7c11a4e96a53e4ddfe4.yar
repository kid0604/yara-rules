rule CobaltStrike_Sleeve_Beacon_Dll_v4_1_and_v4_2
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.dll Versions 4.1 and 4.2"
		hash = "daa42f4380cccf8729129768f3588bb98e4833b0c40ad0620bb575b5674d5fc3"
		rs2 = "9de55f27224a4ddb6b2643224a5da9478999c7b2dea3a3d6b3e1808148012bcf"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		os = "windows"
		filetype = "executable"

	strings:
		$version_sig = { 48 57 8B F2 83 F8 63 0F 87 3C 03 00 00 FF 24 }
		$decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}
