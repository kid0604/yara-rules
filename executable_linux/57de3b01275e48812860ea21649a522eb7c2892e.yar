rule Linux_Cryptominer_Bulz_0998f811
{
	meta:
		author = "Elastic Security"
		id = "0998f811-7be3-4d46-9dcb-1e8a0f19bab5"
		fingerprint = "c8a83bc305998cb6256b004e9d8ce6d5d1618b107e42be139b73807462b53c31"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Bulz"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Cryptominer.Bulz malware"
		filetype = "executable"

	strings:
		$a = { 79 70 E4 39 C5 F9 70 C9 4E C5 91 72 F0 12 C5 F9 72 D0 0E C5 91 }

	condition:
		all of them
}
