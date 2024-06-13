rule Windows_Generic_Threat_492d7223
{
	meta:
		author = "Elastic Security"
		id = "492d7223-4e03-4a77-83e5-ed85e052f846"
		fingerprint = "71a1bce450522a0a6ff38d2f84ab91e2e9db360736c2f7233124a0b0dc4d0431"
		creation_date = "2024-03-26"
		last_modified = "2024-06-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "c0d9c9297836aceb4400bcb0877d1df90ca387f18f735de195852a909c67b7ef"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 55 89 E5 53 57 56 83 EC 24 ?? ?? ?? ?? ?? 31 C9 85 C0 0F 94 C1 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 01 C8 40 FF E0 }

	condition:
		all of them
}
