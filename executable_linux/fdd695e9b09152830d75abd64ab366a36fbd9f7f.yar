rule Linux_Exploit_Local_3b767a1f
{
	meta:
		author = "Elastic Security"
		id = "3b767a1f-5844-4742-a5fd-ef8a3ddb6c12"
		fingerprint = "2bc0dc4de92306076cda6f2d069855b85861375c8b7eb5324f915a1ed10c39e5"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.Local"
		reference_sample = "e05fed9e514cccbdb775f295327d8f8838b73ad12f25e7bb0b9d607ff3d0511c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux local exploit"
		filetype = "executable"

	strings:
		$a = { E3 50 53 89 E1 89 C2 B0 0B CD 80 89 C3 31 C0 40 }

	condition:
		all of them
}
