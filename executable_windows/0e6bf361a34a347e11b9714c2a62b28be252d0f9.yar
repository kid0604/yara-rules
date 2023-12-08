rule CobaltStrike_Resources_Artifact64_v3_1_v3_2_v3_14_and_v4_0
{
	meta:
		description = "Cobalt Strike's resources/artifact64{svcbig.exe,.dll,big.dll,svc.exe} and resources/artifactuac(big)64.dll signature for versions 3.14 to 4.x and resources/artifact32svc.exe for 3.14 to 4.x"
		hash = "2e7a39bd6ac270f8f548855b97c4cef2c2ce7f54c54dd4d1aa0efabeecf3ba90"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		os = "windows"
		filetype = "executable"

	strings:
		$decoderFunction = { 31 ?? EB 0F 41 [2] 03 47 [3] 44 [3] 48 [2] 39 ?? 41 [2] 7C EA 4C [6] E9 }

	condition:
		$decoderFunction
}
