rule CobaltStrike_Resources_Artifact32svc_Exe_v3_1_v3_2_v3_14_and_v4_x
{
	meta:
		description = "Cobalt Strike's resources/artifact32svc(big).exe signature for versions 3.1 and 3.2 (with overlap with v3.14 through v4.x)"
		hash = "871390255156ce35221478c7837c52d926dfd581173818620b738b4b029e6fd9"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		os = "windows"
		filetype = "executable"

	strings:
		$decoderFunc = { 89 ?? B? 04 00 00 00 99 F7 FF 8B [2] 8A [2] 30 }

	condition:
		$decoderFunc
}
