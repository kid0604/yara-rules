rule CobaltStrike_Resources_Beacon_Dll_v1_49
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Version 1.49"
		hash = "52b4bd87e21ee0cbaaa0fc007fd3f894c5fc2c4bae5cbc2a37188de3c2c465fe"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		os = "windows"
		filetype = "executable"

	strings:
		$version_sig = { 48 56 83 F8 1E 0F 87 23 01 00 00 FF 24 }
		$decoder = { B1 ?? 90 30 88 [4] 40 3D A8 01 00 00 7C F2 }

	condition:
		all of them
}
