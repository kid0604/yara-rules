rule CobaltStrike_Resources_Beacon_Dll_v3_14
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Versions 3.14"
		hash = "254c68a92a7108e8c411c7b5b87a2f14654cd9f1324b344f036f6d3b6c7accda"
		rs2 = "87b3eb55a346b52fb42b140c03ac93fc82f5a7f80697801d3f05aea1ad236730"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		os = "windows"
		filetype = "executable"

	strings:
		$version_sig = { 83 FA 5B 77 15 FF 24 }
		$decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}
