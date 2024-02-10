rule Windows_Generic_Threat_d568682a
{
	meta:
		author = "Elastic Security"
		id = "d568682a-94d2-41e7-88db-f6d6499cbdb2"
		fingerprint = "2195cf67cdedfe7531591f65127ef800062d88157126393d0a767837a9023632"
		creation_date = "2024-01-17"
		last_modified = "2024-02-08"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "0d98bc52259e0625ec2f24078cf4ae3233e5be0ade8f97a80ca590a0f1418582"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 28 00 00 0A 28 22 00 00 0A 80 19 00 00 04 28 53 00 00 06 28 2D 00 00 0A 28 5D 00 00 06 16 80 1D 00 00 04 7E 13 00 00 04 7E 15 00 00 04 16 7E 15 00 00 04 8E B7 16 14 FE 06 5B 00 00 06 73 79 00 }

	condition:
		all of them
}
