rule Linux_Exploit_CVE_2012_0056_b39839f4
{
	meta:
		author = "Elastic Security"
		id = "b39839f4-e6f4-44bd-a636-ce355f3c5c6a"
		fingerprint = "f269c4aecbb55e24d9081d7a1e4bd6cfa9799409b3a3d7a6f9bf127f7468dedc"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.CVE-2012-0056"
		reference_sample = "cf569647759e011ff31d8626cea65ed506e8d0ef1d26f3bbb7c02a4060ce58dc"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux exploit CVE-2012-0056"
		filetype = "executable"

	strings:
		$a = { 08 02 7E 3E 8B 45 0C 83 C0 04 8B 00 0F B6 00 3C 2D 75 2F 8B }

	condition:
		all of them
}
