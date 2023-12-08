rule CobaltStrike_Resources_Artifact64_v3_14_to_v4_x
{
	meta:
		description = "Cobalt Strike's resources/artifact64{.exe,.dll,svc.exe,svcbig.exe,big.exe,big.dll,.x64.dll,big.x64.dll} and resource/artifactuac(alt)64.exe signature for versions v3.14 through v4.x"
		hash = "decfcca0018f2cec4a200ea057c804bb357300a67c6393b097d52881527b1c44"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		os = "windows"
		filetype = "executable"

	strings:
		$fmtBuilder = {
			41 ?? 5C 00 00 00
			C7 [3] 5C 00 00 00
			C7 [3] 65 00 00 00
			C7 [3] 70 00 00 00
			C7 [3] 69 00 00 00
			C7 [3] 70 00 00 00
			C7 [3] 5C 00 00 00
			C7 [3] 2E 00 00 00
			89 [3]
			48 [6]
			E8
		}
		$fmtString = "%c%c%c%c%c%c%c%c%cMSSE-%d-server"

	condition:
		all of them
}
