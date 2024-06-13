rule Windows_Generic_Threat_aeaeb5cf
{
	meta:
		author = "Elastic Security"
		id = "aeaeb5cf-2683-4a88-b736-4b8873d92fc5"
		fingerprint = "f6d32006747b083632f551c8ca182b6b4d67a8f130a118e61b0dd2f35d7d8477"
		creation_date = "2024-05-22"
		last_modified = "2024-06-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "f57d955d485904f0c729acff9db1de9cb42f32af993393d58538f07fa273b431"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 55 8B EC 8B 4D 08 33 C0 66 39 01 74 0B 8D 49 00 40 66 83 3C 41 00 75 F8 8D 04 45 02 00 00 00 50 FF 75 0C 51 ?? ?? ?? ?? ?? 83 C4 0C 5D C3 CC CC 55 8B EC 6A 00 FF 75 08 }

	condition:
		all of them
}
