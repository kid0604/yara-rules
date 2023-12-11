rule Linux_Cryptominer_Xmrminer_c6218e30
{
	meta:
		author = "Elastic Security"
		id = "c6218e30-1a49-46ea-aac8-5f0f652156c5"
		fingerprint = "c3171cf17ff3b0ca3d5d62fd4c2bd02a4e0a8616a84ea5ef9e78307283e4a360"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Xmrminer"
		reference_sample = "b43ddd8e355b0c538c123c43832e7c8c557e4aee9e914baaed0866ee5d68ee55"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Cryptominer.Xmrminer malware"
		filetype = "executable"

	strings:
		$a = { AC 24 B0 00 00 00 48 89 FA 66 0F EF DD 48 C1 E2 20 66 41 0F }

	condition:
		all of them
}
