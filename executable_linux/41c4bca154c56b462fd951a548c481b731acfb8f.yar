rule Linux_Backdoor_Generic_babf9101
{
	meta:
		author = "Elastic Security"
		id = "babf9101-1e6e-4268-a530-e99e2c905b0d"
		fingerprint = "a578b052910962523f26f14f0d0494481fe0777c01d9f6816c7ab53083a47adc"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Backdoor.Generic"
		reference_sample = "9ea73d2c2a5f480ae343846e2b6dd791937577cb2b3d8358f5b6ede8f3696b86"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects a generic Linux backdoor"
		filetype = "executable"

	strings:
		$a = { C4 10 89 45 F4 83 7D F4 00 79 1F 83 EC 0C 68 22 }

	condition:
		all of them
}
