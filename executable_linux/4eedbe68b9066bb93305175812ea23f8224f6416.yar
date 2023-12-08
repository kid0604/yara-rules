rule Linux_Trojan_Sshdoor_3e81b1b7
{
	meta:
		author = "Elastic Security"
		id = "3e81b1b7-71bd-4876-a616-ca49ce73c2da"
		fingerprint = "7849bb7283adb25c2ee492efd8d9b2c63de7ae701a69e1892cdc25175996b227"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Sshdoor"
		reference_sample = "def4de838d58c70f9f0ae026cdad3bf09b711a55af97ed20804fa1e34e7b59e9"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Sshdoor with fingerprint 3e81b1b7"
		filetype = "executable"

	strings:
		$a = { 24 24 48 89 E7 C1 EE 05 83 E6 01 FF D3 8B 54 24 28 31 C0 BE 5A 00 }

	condition:
		all of them
}
