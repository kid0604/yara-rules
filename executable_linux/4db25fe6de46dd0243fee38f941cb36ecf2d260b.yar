rule Linux_Generic_Threat_0b770605
{
	meta:
		author = "Elastic Security"
		id = "0b770605-db33-4028-b186-b1284da3e3fe"
		fingerprint = "d771f9329fec5e70b515512b58d77bb82b3c472cd0608901a6e6f606762d2d7e"
		creation_date = "2024-01-17"
		last_modified = "2024-02-13"
		threat_name = "Linux.Generic.Threat"
		reference_sample = "99418cbe1496d5cd4177a341e6121411bc1fab600d192a3c9772e8e6cd3c4e88"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux generic threat"
		filetype = "executable"

	strings:
		$a1 = { 68 65 79 20 73 63 61 6E 20 72 65 74 61 72 64 }
		$a2 = { 5B 62 6F 74 70 6B 74 5D 20 43 6F 6D 6D 69 74 74 69 6E 67 20 53 75 69 63 69 64 65 }

	condition:
		all of them
}
