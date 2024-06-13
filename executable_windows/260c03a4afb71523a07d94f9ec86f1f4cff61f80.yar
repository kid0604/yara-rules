rule Windows_Generic_Threat_7407eb79
{
	meta:
		author = "Elastic Security"
		id = "7407eb79-69fd-4f5c-b883-ceb74fbdc9d5"
		fingerprint = "f1dbb42fdd80020fa2b30beb50ded6b8b3fe4b023935cef9bd32b3cb0a095654"
		creation_date = "2024-02-20"
		last_modified = "2024-06-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "9ae0f053c8e2c4f4381eac8265170b79301d4a22ec1fdb86e5eb212c51a75d14"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 83 EC 18 8B 45 08 8B 40 08 89 45 E8 8B 45 08 8B 40 0C 89 45 EC 8B 45 EC 83 C0 0C 89 45 F0 8B 45 F0 8B 00 89 45 F8 83 65 F4 00 E8 00 00 00 00 58 89 45 F4 8B 45 F8 3B 45 F0 74 31 8B 45 }

	condition:
		all of them
}
