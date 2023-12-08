rule Linux_Trojan_Mobidash_29b86e6a
{
	meta:
		author = "Elastic Security"
		id = "29b86e6a-fcad-49ac-ae78-ce28987f7363"
		fingerprint = "5d7d930f39e435fc22921571fe96db912eed79ec630d4ed60da6f007073b7362"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mobidash"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux Trojan Mobidash (29b86e6a)"
		filetype = "executable"

	strings:
		$a = { 2E 10 73 2E 10 02 47 2E 10 56 2E 10 5C 2E 10 4E 2E 10 49 2E 10 }

	condition:
		all of them
}
