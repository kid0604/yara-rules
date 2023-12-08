rule Linux_Trojan_Mirai_feaa98ff
{
	meta:
		author = "Elastic Security"
		id = "feaa98ff-6cd9-40bb-8c4f-ea7c79b272f3"
		fingerprint = "0bc8ba390a11e205624bc8035b1d1e22337a5179a81d354178fa2546c61cdeb0"
		creation_date = "2022-09-12"
		last_modified = "2022-10-18"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "2382996a8fd44111376253da227120649a1a94b5c61739e87a4e8acc1130e662"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai"
		filetype = "executable"

	strings:
		$a = { 0F FD FD FD FD FD FD 7A 03 41 74 5E 42 31 FD FD 6E FD FD FD FD }

	condition:
		all of them
}
