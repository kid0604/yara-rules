rule Linux_Trojan_Gafgyt_751acb94
{
	meta:
		author = "Elastic Security"
		id = "751acb94-cb23-4949-a4dd-87985c47379e"
		fingerprint = "dbdfdb455868332e9fbadd36c084d0927a3dd8ab844f0b1866e914914084cd4b"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Gafgyt"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt variant 751acb94"
		filetype = "executable"

	strings:
		$a = { 20 54 6F 20 43 6F 6E 6E 65 63 74 21 20 00 53 75 63 63 65 73 66 }

	condition:
		all of them
}
