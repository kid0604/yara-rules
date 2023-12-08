rule Linux_Exploit_CVE_2009_1897_6cf0a073
{
	meta:
		author = "Elastic Security"
		id = "6cf0a073-571e-48ef-be58-807bff1a5e97"
		fingerprint = "8fcb3687d4ec5dd467d937787f0659448a91446f92a476ff7ba471a02d6b07a9"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.CVE-2009-1897"
		reference_sample = "85f371bf73ee6d8fcb6fa9a8a68b38c5e023151257fd549855c4c290cc340724"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux exploit CVE-2009-1897"
		filetype = "executable"

	strings:
		$a = { 31 C0 85 DB 78 28 45 31 C9 41 89 D8 B9 02 00 00 00 BA 01 00 }

	condition:
		all of them
}
