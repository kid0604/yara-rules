rule Linux_Exploit_Intfour_0ca45cd3
{
	meta:
		author = "Elastic Security"
		id = "0ca45cd3-089c-4d7f-9088-dc972c14bd9d"
		fingerprint = "8926a8cfd7f3adf29e399a945592063039b80dcc0545b133b453aaf198d31461"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.Intfour"
		reference_sample = "9d32c5447aa5182b4be66b7a283616cf531a2fd3ba3dde1bc363b24d8b22682f"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Exploit.Intfour"
		filetype = "executable"

	strings:
		$a = { 6D 28 63 6F 64 65 2C 20 31 30 32 34 2C 20 26 6E 65 65 64 6C 65 }

	condition:
		all of them
}
