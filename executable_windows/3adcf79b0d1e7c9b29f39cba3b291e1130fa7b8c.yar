rule CobaltStrike_Resources_Artifact64_v1_49_v2_x_v3_0_v3_3_thru_v3_14
{
	meta:
		description = "Cobalt Strike's resources/artifact64{.dll,.exe,big.exe,big.dll,bigsvc.exe,big.x64.dll} and resources/rtifactuac(alt)64.dll signature for versions v1.49, v2.x, v3.0, and v3.3 through v3.14"
		hash = "9ec57d306764517b5956b49d34a3a87d4a6b26a2bb3d0fdb993d055e0cc9920d"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		os = "windows"
		filetype = "executable"

	strings:
		$a = { 8B [2] 48 98 48 [2] 48 [3] 8B [2] 48 98 48 [3] 44 [3] 8B [2] 89 ?? C1 ?? 1F C1 ?? 1E 01 ?? 83 ?? 03 29 ?? 48 98 48 [3] 0F B6 00 44 [2] 88 }

	condition:
		$a
}
