rule Linux_Trojan_Tsunami_47f93be2
{
	meta:
		author = "Elastic Security"
		id = "47f93be2-687c-42d2-9627-29f114beb234"
		fingerprint = "f4a2262cfa0f0db37e15149cf33e639fd2cd6d58f4b89efe7860f73014b47c4e"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Tsunami"
		reference_sample = "2e4f89c76dfefd4b2bfd1cf0467ac0324026355723950d12d7ed51195fd998cf"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux Trojan Tsunami"
		filetype = "executable"

	strings:
		$a = { FA 48 63 C6 48 89 94 C5 70 FF FF FF 8B 85 5C FF FF FF 8D 78 01 48 8D 95 60 FF }

	condition:
		all of them
}
