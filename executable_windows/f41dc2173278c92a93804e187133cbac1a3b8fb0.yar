rule Windows_Generic_Threat_55d6a1ab
{
	meta:
		author = "Elastic Security"
		id = "55d6a1ab-2041-44a5-ae0e-23671fa2b001"
		fingerprint = "cd81b61929b18d59630814718443c4b158f9dcc89c7d03a46a531ffc5843f585"
		creation_date = "2024-01-07"
		last_modified = "2024-01-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "1ca6ed610479b5aaaf193a2afed8f2ca1e32c0c5550a195d88f689caab60c6fb"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 51 51 31 33 37 32 33 39 32 34 38 20 }
		$a2 = { 74 65 6E 63 65 6E 74 3A 2F 2F 6D 65 73 73 61 67 65 2F 3F 75 69 6E 3D 31 33 37 32 33 39 32 34 38 26 53 69 74 65 3D 63 66 }

	condition:
		all of them
}
