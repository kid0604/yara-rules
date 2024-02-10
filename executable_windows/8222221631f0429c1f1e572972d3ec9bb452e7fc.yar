rule Windows_Generic_Threat_b2a054f8
{
	meta:
		author = "Elastic Security"
		id = "b2a054f8-160f-4932-b5fe-c7d78a1f9b74"
		fingerprint = "09f1724963bfdde810b61d80049def388c89f6a21195e90a869bb22d19d074de"
		creation_date = "2024-01-12"
		last_modified = "2024-02-08"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "63d2478a5db820731a48a7ad5a20d7a4deca35c6b865a17de86248bef7a64da7"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 7E 38 7E 40 7E 44 48 4C 2A 7E 7E 58 5D 5C }
		$a2 = { 39 7B 34 74 26 39 3A 62 3A 66 25 6A }
		$a3 = { 5B 50 44 7E 66 7E 71 7E 77 7E 7C 7E }

	condition:
		all of them
}
