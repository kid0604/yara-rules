rule Linux_Trojan_Gafgyt_33801844
{
	meta:
		author = "Elastic Security"
		id = "33801844-50b1-4968-a1b7-d106f16519ee"
		fingerprint = "36218345b9ce4aaf50b5df1642c00ac5caa744069e952eb6008a9a57a37dbbdc"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Gafgyt"
		reference_sample = "2ceff60e88c30c02c1c7b12a224aba1895669aad7316a40b575579275b3edbb3"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt"
		filetype = "executable"

	strings:
		$a = { 45 F8 48 83 E8 01 0F B6 00 3C 0D 75 0B 48 8B 45 F8 0F B6 00 }

	condition:
		all of them
}
