rule Windows_Generic_Threat_bf7aae24
{
	meta:
		author = "Elastic Security"
		id = "bf7aae24-f89a-4cc6-9a15-fc29aa80af98"
		fingerprint = "9304e9069424d43613ef9a5484214d0e3620245ef9ae64bae7d825f5f69d90c0"
		creation_date = "2023-12-18"
		last_modified = "2024-01-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "6dfc63894f15fc137e27516f2d2a56514c51f25b41b00583123142cf50645e4e"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 48 33 F6 44 8B EE 48 89 74 24 20 8B EE 48 89 B4 24 A8 00 00 00 44 8B F6 48 89 74 24 28 44 8B E6 E8 BF FF FF FF 4C 8B F8 8D 5E 01 B8 4D 5A 00 00 66 41 39 07 75 1B 49 63 57 3C 48 8D 4A }

	condition:
		all of them
}
