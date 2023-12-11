rule Linux_Trojan_Generic_181054af
{
	meta:
		author = "Elastic Security"
		id = "181054af-dc05-4981-8a57-ea17ffd6241f"
		fingerprint = "8ef033ac0fccd10cdf2e66446461b7c8b29574e5869440a1972dbe4bb5fbed89"
		creation_date = "2022-01-05"
		last_modified = "2022-01-26"
		threat_name = "Linux.Trojan.Generic"
		reference_sample = "e677f1eed0dbb4c680549e0bf86d92b0a28a85c6d571417baaba0d0719da5f93"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Generic"
		filetype = "executable"

	strings:
		$a = { 6D 6F 64 00 73 65 74 75 74 78 65 6E 74 00 67 6D 74 69 6D 65 00 }

	condition:
		all of them
}
