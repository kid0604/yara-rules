rule Linux_Trojan_Gafgyt_f11e98be
{
	meta:
		author = "Elastic Security"
		id = "f11e98be-bf81-480e-b2d1-dcc748c6869d"
		fingerprint = "8cdf2acffd0cdce48ceaffa6682d2f505c557b873e4f418f4712dfa281a3095a"
		creation_date = "2022-09-12"
		last_modified = "2022-10-18"
		threat_name = "Linux.Trojan.Gafgyt"
		reference_sample = "79a75c8aa5aa0d1edef5965e1bcf8ba2f2a004a77833a74870b8377d7fde89cf"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt variant with fingerprint f11e98be"
		filetype = "executable"

	strings:
		$a = { FD 40 00 09 FD 21 FD FD 08 48 FD 80 3E 00 75 FD FD 4C 24 48 0F FD }

	condition:
		all of them
}
