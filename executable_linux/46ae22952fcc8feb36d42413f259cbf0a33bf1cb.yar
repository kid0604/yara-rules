rule Linux_Trojan_Gafgyt_6321b565
{
	meta:
		author = "Elastic Security"
		id = "6321b565-ed25-4bf2-be4f-3ffa0e643085"
		fingerprint = "c1d286e82426cbf19fc52836ef9a6b88c1f6e144967f43760df93cf1ab497d07"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Gafgyt"
		reference_sample = "cd48addd392e7912ab15a5464c710055f696990fab564f29f13121e7a5e93730"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt variant with ID 6321b565"
		filetype = "executable"

	strings:
		$a = { D8 89 D0 01 C0 01 D0 C1 E0 03 8B 04 08 83 E0 1F 0F AB 84 9D 58 FF }

	condition:
		all of them
}
