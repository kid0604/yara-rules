rule Linux_Trojan_Gafgyt_f3d83a74
{
	meta:
		author = "Elastic Security"
		id = "f3d83a74-2888-435a-9a3c-b7de25084e9a"
		fingerprint = "1c5df68501b688905484ed47dc588306828aa7c114644428e22e5021bb39bd4a"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Gafgyt"
		reference_sample = "275cbd5d3b3d8c521649b95122d90d1ca9b7ae1958b721bdc158aaa2d31d49df"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt with fingerprint f3d83a74"
		filetype = "executable"

	strings:
		$a = { DC 00 74 1B 83 7D E0 0A 75 15 83 7D E4 00 79 0F C7 45 C8 01 00 }

	condition:
		all of them
}
