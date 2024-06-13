rule Windows_Generic_Threat_d7e5ec2d
{
	meta:
		author = "Elastic Security"
		id = "d7e5ec2d-bcd1-41a3-80de-12808b9034c9"
		fingerprint = "e679e6917c5055384c0492e4a8a7538b41e5239b78e2167b04fffa3693f036bb"
		creation_date = "2024-02-20"
		last_modified = "2024-06-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "fe711664a565566cbc710d5e678a9a30063a2db151ebec226e2abcd24c0a7e68"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 83 C4 F8 89 45 FC 8B 45 FC E8 17 FE FF FF 83 FA 00 75 03 83 F8 FF 77 16 8B 45 FC E8 F1 FE FF FF 83 FA 00 75 03 83 F8 FF 77 04 33 C0 EB 02 B0 01 88 45 FB 8A 45 FB 59 59 5D C3 8D 40 00 }

	condition:
		all of them
}
