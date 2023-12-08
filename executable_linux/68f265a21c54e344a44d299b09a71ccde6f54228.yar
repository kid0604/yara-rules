rule Linux_Exploit_CVE_2010_3301_79d52efd
{
	meta:
		author = "Elastic Security"
		id = "79d52efd-7955-4aa3-afbe-b7d172c30f34"
		fingerprint = "22235427bc621e07c16c365ddbf22a4e1c04d7a0f23c3e4c46d967d908256567"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.CVE-2010-3301"
		reference_sample = "53a2163ad17a414d9db95f5287d9981c9410e7eaeea096610ba622eb763a6970"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Linux exploit for CVE-2010-3301"
		filetype = "executable"

	strings:
		$a = { E8 3B F9 FF FF 83 7D D4 FF 75 16 48 8D 3D 35 03 }

	condition:
		all of them
}
