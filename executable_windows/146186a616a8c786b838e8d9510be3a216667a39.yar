rule Windows_Generic_Threat_c8424507
{
	meta:
		author = "Elastic Security"
		id = "c8424507-34e1-4649-a4e4-3e0a0f62dfb0"
		fingerprint = "8dfb14903b32c118492ae7e0aab9cf634c58ea93fcbc7759615209f61b3b3d6b"
		creation_date = "2024-05-22"
		last_modified = "2024-06-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "d556b02733385b823cfe4db7e562e90aa520e2e6fb00fceb76cc0a6a1ff47692"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 78 75 73 65 68 6F 62 69 6D 6F 7A 61 63 6F 67 6F 6A 69 68 6F 67 69 76 6F }
		$a2 = { 62 65 6D 69 74 69 76 65 67 69 77 6F 6D 65 7A 75 76 65 62 61 67 }

	condition:
		all of them
}
