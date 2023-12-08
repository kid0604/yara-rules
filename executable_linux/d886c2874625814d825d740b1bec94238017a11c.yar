rule Linux_Exploit_CVE_2021_3156_f3fb10cd
{
	meta:
		author = "Elastic Security"
		id = "f3fb10cd-1d49-420f-8740-5c8990560943"
		fingerprint = "66aca7d13fb9c5495f17b7891e388db0a746d8827c8ae302a6cb8d86f7630bbb"
		creation_date = "2021-09-15"
		last_modified = "2021-09-21"
		threat_name = "Linux.Exploit.CVE-2021-3156"
		reference_sample = "65fb8baa5ec3bfb4473e4b2f565b461dd59989d43c72b1c5ec2e1a68baa8b51a"
		severity = 100
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux exploit CVE-2021-3156"
		filetype = "executable"

	strings:
		$a1 = "/usr/bin/sudoedit" fullword
		$a2 = "<smash_len_a>" fullword

	condition:
		all of them
}
