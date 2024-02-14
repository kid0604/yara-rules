rule Linux_Generic_Threat_4a46b0e1
{
	meta:
		author = "Elastic Security"
		id = "4a46b0e1-b0d4-423c-9600-f594d3a48a33"
		fingerprint = "2ae70fc399a228284a3827137db2a5b65180811caa809288df44e5b484eb1966"
		creation_date = "2024-02-01"
		last_modified = "2024-02-13"
		threat_name = "Linux.Generic.Threat"
		reference_sample = "3ba47ba830ab8deebd9bb906ea45c7df1f7a281277b44d43c588c55c11eba34a"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux generic threat"
		filetype = "executable"

	strings:
		$a1 = { 20 28 76 69 61 20 53 79 73 74 65 6D 2E 6D 61 70 29 }
		$a2 = { 20 5B 2B 5D 20 52 65 73 6F 6C 76 65 64 20 25 73 20 74 6F 20 25 70 25 73 }

	condition:
		all of them
}
