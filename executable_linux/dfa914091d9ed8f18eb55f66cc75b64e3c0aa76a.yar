rule Linux_Trojan_Xorddos_8677dca3
{
	meta:
		author = "Elastic Security"
		id = "8677dca3-e36b-439f-bc55-76d951114020"
		fingerprint = "4d276b225f412b3879db19546c09d1dea2ee417c61ab6942c411bc392fee8e26"
		creation_date = "2022-09-12"
		last_modified = "2022-10-18"
		threat_name = "Linux.Trojan.Xorddos"
		reference_sample = "23813dc4aa56683e1426e5823adc3aab854469c9c0f3ec1a3fad40fa906929f2"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Xorddos"
		filetype = "executable"

	strings:
		$a = { F2 5E 83 C2 03 8B FF C1 E2 05 9C 83 C5 69 9D 8D 6D 97 03 C2 56 8B 74 }

	condition:
		all of them
}
