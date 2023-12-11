rule Linux_Hacktool_Portscan_e57b0a0c
{
	meta:
		author = "Elastic Security"
		id = "e57b0a0c-66b8-488b-b19d-ae06623645fd"
		fingerprint = "829c7d271ae475ef06d583148bbdf91af67ce4c7a831da73cc52e8406e7e8f9e"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Hacktool.Portscan"
		reference_sample = "f8ee385316b60ee551565876287c06d76ac5765f005ca584d1ca6da13a6eb619"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Hacktool.Portscan activity"
		filetype = "executable"

	strings:
		$a = { 10 83 7D 08 03 75 2B 83 EC 0C 8B 45 0C 83 C0 08 FF 30 8B 45 0C 83 }

	condition:
		all of them
}
