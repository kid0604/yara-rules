rule Linux_Hacktool_Flooder_a598192a
{
	meta:
		author = "Elastic Security"
		id = "a598192a-c804-4c57-9cc3-c2205cb431d3"
		fingerprint = "61cb72180283746ebbd82047baffc4bf2384658019970c4dceadfb5c946abcd2"
		creation_date = "2021-06-28"
		last_modified = "2021-09-16"
		threat_name = "Linux.Hacktool.Flooder"
		reference = "101f2240cd032831b9c0930a68ea6f74688f68ae801c776c71b488e17bc71871"
		severity = "100"
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Hacktool.Flooder"
		filetype = "executable"

	strings:
		$a = { 8D 65 D8 5B 5E 5F C9 C3 8D 36 55 89 E5 83 EC 18 57 56 53 8B }

	condition:
		all of them
}
