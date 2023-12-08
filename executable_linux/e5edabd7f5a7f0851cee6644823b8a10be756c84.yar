rule Linux_Trojan_Gafgyt_71e487ea
{
	meta:
		author = "Elastic Security"
		id = "71e487ea-a592-469c-a03e-0c64d2549e74"
		fingerprint = "8df69968ddfec5821500949015192b6cdbc188c74f785a272effd7bc9707f661"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Gafgyt"
		reference_sample = "b8d044f2de21d20c7e4b43a2baf5d8cdb97fba95c3b99816848c0f214515295b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt"
		filetype = "executable"

	strings:
		$a = { E0 8B 45 D8 8B 04 D0 8D 50 01 83 EC 0C 8D 85 40 FF FF FF 50 }

	condition:
		all of them
}
