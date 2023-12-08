rule Linux_Trojan_Ipstorm_3c43d4a7
{
	meta:
		author = "Elastic Security"
		id = "3c43d4a7-185a-468b-a73d-82f579de98c1"
		fingerprint = "cf6812f8f0ee7951a70bec3839b798a574d536baae4cf37cda6eebf570cab0be"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Ipstorm"
		reference_sample = "5103133574615fb49f6a94607540644689be017740d17005bc08b26be9485aa7"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Ipstorm"
		filetype = "executable"

	strings:
		$a = { 48 8D 54 24 58 31 F6 EB 11 48 8B 84 24 88 00 00 00 48 89 F1 48 }

	condition:
		all of them
}
