rule Linux_Exploit_Enoket_79b52a4c
{
	meta:
		author = "Elastic Security"
		id = "79b52a4c-80cd-4fe1-aa6c-463e2cdd64ac"
		fingerprint = "84be6877d6b1eb091de9817a5cf0ecba5e0e82089a6dd1dc0af2e91b01fe4003"
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
		$a = { 66 6F 75 6E 64 20 61 74 20 30 78 25 30 34 78 20 69 6E 20 74 }

	condition:
		all of them
}
