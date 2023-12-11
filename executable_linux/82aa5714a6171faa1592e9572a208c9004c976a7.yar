rule Linux_Trojan_Gafgyt_807911a2
{
	meta:
		author = "Elastic Security"
		id = "807911a2-f6ec-4e65-924f-61cb065dafc6"
		fingerprint = "f409037091b7372f5a42bbe437316bd11c655e7a5fe1fcf83d1981cb5c4a389f"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Gafgyt"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt variant 807911a2"
		filetype = "executable"

	strings:
		$a = { FE 48 39 F3 0F 94 C2 48 83 F9 FF 0F 94 C0 84 D0 74 16 4B 8D }

	condition:
		all of them
}
