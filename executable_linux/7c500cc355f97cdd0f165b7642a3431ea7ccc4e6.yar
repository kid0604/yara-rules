rule Linux_Trojan_Mirai_70ef58f1
{
	meta:
		author = "Elastic Security"
		id = "70ef58f1-ac74-4e33-ae03-e68d1d5a4379"
		fingerprint = "c46eac9185e5f396456004d1e0c42b54a9318e0450f797c55703122cfb8fea89"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "fc8741f67f39e7409ab2c6c62d4f9acdd168d3e53cf6976dd87501833771cacb"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai variant with fingerprint 70ef58f1"
		filetype = "executable"

	strings:
		$a = { 89 D0 8B 19 01 D8 0F B6 5C 24 10 30 18 89 D0 8B 19 01 D8 0F B6 5C }

	condition:
		all of them
}
