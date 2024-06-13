rule Windows_Generic_Threat_4c37e16e
{
	meta:
		author = "Elastic Security"
		id = "4c37e16e-b7ca-449a-a09f-836706b2f66a"
		fingerprint = "9fbd2883fb0140de50df755f7099a0dc3cf377ee350710108fef96c912f43460"
		creation_date = "2024-03-04"
		last_modified = "2024-06-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "d83a8ed5e192b3fe9d74f3a9966fa094d23676c7e6586c9240d97c252b8e4e74"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 2E 3F 41 56 43 44 72 6F 70 41 70 69 40 40 }
		$a2 = { 2D 2D 77 77 6A 61 75 67 68 61 6C 76 6E 63 6A 77 69 61 6A 73 2D 2D }

	condition:
		all of them
}
