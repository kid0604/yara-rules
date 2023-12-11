rule Linux_Trojan_Gafgyt_e0673a90
{
	meta:
		author = "Elastic Security"
		id = "e0673a90-165e-4347-a965-e8d14fdf684b"
		fingerprint = "6834f65d54bbfb926f986fe2dd72cd30bf9804ed65fcc71c2c848e72350f386a"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Gafgyt"
		reference_sample = "c5a317d0d8470814ff343ce78ad2428ebb3f036763fcf703a589b6c4d33a3ec6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt variant with fingerprint e0673a90"
		filetype = "executable"

	strings:
		$a = { 45 E8 0F B6 00 84 C0 74 17 48 8B 75 E8 48 FF C6 48 8B 7D F0 48 }

	condition:
		all of them
}
