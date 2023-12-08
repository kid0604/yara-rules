rule Linux_Trojan_Winnti_4c5a1865
{
	meta:
		author = "Elastic Security"
		id = "4c5a1865-ff41-445b-8616-c83b87498c2b"
		fingerprint = "685fe603e04ff123b3472293d3d83e2dc833effd1a7e6c616ff17ed61df0004c"
		creation_date = "2021-06-28"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Winnti"
		reference = "0d963a713093fc8e5928141f5747640c9b43f3aadc8a5478c949f7ec364b28ad"
		severity = "100"
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Trojan.Winnti malware"
		filetype = "executable"

	strings:
		$a = { C1 E8 1F 84 C0 75 7B 85 D2 89 D5 7E 75 8B 47 0C 39 C6 7D 6E 44 8D }

	condition:
		all of them
}
