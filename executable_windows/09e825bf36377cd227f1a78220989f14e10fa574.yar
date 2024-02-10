rule Windows_Generic_Threat_747b58af
{
	meta:
		author = "Elastic Security"
		id = "747b58af-6edb-42f2-8a1b-e462399ef61e"
		fingerprint = "79faab4fda6609b2c95d24de92a3a417d2f5e58f3f83c856fa9f32e80bed6f37"
		creation_date = "2024-01-17"
		last_modified = "2024-02-08"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "ee28e93412c59d63155fd79bc99979a5664c48dcb3c77e121d17fa985fcb0ebe"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 5C 43 3D 5D 78 48 73 66 40 22 33 2D 34 }
		$a2 = { 79 5A 4E 51 61 4A 21 43 43 56 31 37 74 6B }
		$a3 = { 66 72 7A 64 48 49 2D 4E 3A 4D 23 43 }

	condition:
		all of them
}
