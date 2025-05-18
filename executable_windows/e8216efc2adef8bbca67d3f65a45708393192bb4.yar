rule Windows_Generic_MalCert_e659d934
{
	meta:
		author = "Elastic Security"
		id = "e659d934-f525-4051-b50f-8ac24f441854"
		fingerprint = "4116d6a514cd07e937fd2c2b0d53ae9ce78d553d8faf2ea2f8d4bcbc2034ad23"
		creation_date = "2025-02-05"
		last_modified = "2025-02-10"
		threat_name = "Windows.Generic.MalCert"
		reference_sample = "60ba61b8556e3535d9c66a5ea08bbd37fb07f7a03a35ce4663e9d8179186e1fc"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic malicious certificate"
		filetype = "executable"

	strings:
		$a1 = { 01 02 02 10 47 88 4E 54 A5 98 A9 0B FF 2B D3 18 38 01 02 67 }

	condition:
		all of them
}
