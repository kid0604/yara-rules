rule Linux_Trojan_Iroffer_0de95cab
{
	meta:
		author = "Elastic Security"
		id = "0de95cab-c671-44f0-a85e-5a5634e906f7"
		fingerprint = "42c1ab8af313ec3c475535151ee67cac93ab6a25252b52b1e09c166065fb2760"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Iroffer"
		reference_sample = "717bea3902109d1b1d57e57c26b81442c0705af774139cd73105b2994ab89514"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Iroffer"
		filetype = "executable"

	strings:
		$a = { 45 41 52 52 45 43 4F 52 44 53 00 53 68 6F 77 20 49 6E 66 6F }

	condition:
		all of them
}
