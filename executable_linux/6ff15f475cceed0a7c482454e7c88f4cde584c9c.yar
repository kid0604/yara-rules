rule Linux_Exploit_Enoket_c77c0d6d
{
	meta:
		author = "Elastic Security"
		id = "c77c0d6d-7f5c-4618-b6f6-3c1ddc70783c"
		fingerprint = "739e23abbd2971d6ff24c94a87d7aab082aec85f9cd7eb3a168b35fa22f32eb9"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.Enoket"
		reference_sample = "3ae8f7e7df62316400d0c5fe0139d7a48c9f184e92706b552aad3d827d3dbbbf"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Exploit.Enoket"
		filetype = "executable"

	strings:
		$a = { 6E 64 20 74 68 65 20 77 6F 72 6C 64 2C 20 6F 6E 65 20 68 61 }

	condition:
		all of them
}
