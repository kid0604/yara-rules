rule Linux_Generic_Threat_5d5fd28e
{
	meta:
		author = "Elastic Security"
		id = "5d5fd28e-ae8f-4b6f-ad95-57725550fcef"
		fingerprint = "3a24edfbafc0abee418998d3a6355f4aa2659d68e27db502149a34266076ed15"
		creation_date = "2024-02-21"
		last_modified = "2024-06-12"
		threat_name = "Linux.Generic.Threat"
		reference_sample = "5b179a117e946ce639e99ff42ab70616ed9f3953ff90b131b4b3063f970fa955"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux generic threat"
		filetype = "executable"

	strings:
		$a1 = { 2F 75 73 72 2F 62 69 6E 2F 77 64 31 }
		$a2 = { 2F 75 73 72 2F 62 69 6E 2F 63 64 31 }
		$a3 = { 2F 75 73 72 2F 62 69 6E 2F 63 64 74 }

	condition:
		all of them
}
