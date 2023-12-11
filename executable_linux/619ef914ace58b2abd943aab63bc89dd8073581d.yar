rule Linux_Trojan_Gafgyt_3f8cf56e
{
	meta:
		author = "Elastic Security"
		id = "3f8cf56e-a8cb-4c03-8829-f1daa3dc64a8"
		fingerprint = "77306f0610515434371f70f2b42c895cdc5bbae2ef6919cf835b3cfe2e4e4976"
		creation_date = "2021-06-28"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Gafgyt"
		reference = "1878f0783085cc6beb2b81cfda304ec983374264ce54b6b98a51c09aea9f750d"
		severity = "100"
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt variant with fingerprint 3f8cf56e"
		filetype = "executable"

	strings:
		$a = { 45 2F DA E8 E9 CC E4 F4 39 55 E2 9E 33 0E C0 F0 FB 26 93 31 }

	condition:
		all of them
}
