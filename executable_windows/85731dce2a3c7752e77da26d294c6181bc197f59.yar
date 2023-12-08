rule CobaltStrike_Resources_Beacon_Dll_v3_11_bugfix_and_v3_12
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Versions 3.11-bugfix and 3.12"
		hash = "5912c96fffeabb2c5c5cdd4387cfbfafad5f2e995f310ace76ca3643b866e3aa"
		rs2 = "4476a93abe48b7481c7b13dc912090b9476a2cdf46a1c4287b253098e3523192"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		os = "windows"
		filetype = "executable"

	strings:
		$version_sig = { 48 57 8B FA 83 F8 50 0F 87 0D 03 00 00 FF 24 }
		$decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}
