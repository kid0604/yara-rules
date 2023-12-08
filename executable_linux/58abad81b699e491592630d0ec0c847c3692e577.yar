rule Linux_Trojan_Mirai_76bbc4ca
{
	meta:
		author = "Elastic Security"
		id = "76bbc4ca-e6da-40f7-8ba6-139ec8393f35"
		fingerprint = "4206c56b538eb1dd97e8ba58c5bab6e21ad22a0f8c11a72f82493c619d22d9b7"
		creation_date = "2021-06-28"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference = "1a9ff86a66d417678c387102932a71fd879972173901c04f3462de0e519c3b51"
		severity = "100"
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai variant with fingerprint 76bbc4ca"
		filetype = "executable"

	strings:
		$a = { 10 40 2D E9 00 40 A0 E1 28 20 84 E2 0C 00 92 E8 3B F1 FF EB }

	condition:
		all of them
}
