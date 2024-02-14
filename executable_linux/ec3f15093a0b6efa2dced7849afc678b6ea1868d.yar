rule Linux_Generic_Threat_a658b75f
{
	meta:
		author = "Elastic Security"
		id = "a658b75f-3520-4ec6-b3d4-674bc22380b3"
		fingerprint = "112be9d42b300ce4c2e0d50c9e853d3bdab5d030a12d87aa9bae9affc67cd6cd"
		creation_date = "2024-01-17"
		last_modified = "2024-02-13"
		threat_name = "Linux.Generic.Threat"
		reference_sample = "df430ab9f5084a3e62a6c97c6c6279f2461618f038832305057c51b441c648d9"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux generic threat"
		filetype = "executable"

	strings:
		$a1 = { 6D 61 69 6E 2E 45 6E 63 72 79 70 74 46 69 6C 65 52 65 61 64 57 72 69 74 65 }
		$a2 = { 6D 61 69 6E 2E 53 63 61 6E 57 61 6C 6B 65 72 }

	condition:
		all of them
}
