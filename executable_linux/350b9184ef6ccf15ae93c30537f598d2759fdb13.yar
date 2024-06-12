rule Linux_Generic_Threat_bd35454b
{
	meta:
		author = "Elastic Security"
		id = "bd35454b-a0dd-4925-afae-6416f3695826"
		fingerprint = "721aa441a2567eab29c9bc76f12d0fdde8b8a124ca5a3693fbf9821f5b347825"
		creation_date = "2024-02-21"
		last_modified = "2024-06-12"
		threat_name = "Linux.Generic.Threat"
		reference_sample = "cd729507d2e17aea23a56a56e0c593214dbda4197e8a353abe4ed0c5fbc4799c"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects a generic threat on Linux systems"
		filetype = "executable"

	strings:
		$a1 = { 6D 61 69 6E 2E 65 6E 63 72 79 70 74 5F 66 69 6C 65 }
		$a2 = { 57 68 61 74 20 67 75 61 72 61 6E 74 65 65 73 3F }

	condition:
		all of them
}
