rule Linux_Trojan_Tsunami_8a11f9be
{
	meta:
		author = "Elastic Security"
		id = "8a11f9be-dc85-4695-9f38-80ca0304780e"
		fingerprint = "91e2572a3bb8583e20042578e95e1746501c6a71ef7635af2c982a05b18d7c6d"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Tsunami"
		reference_sample = "1f773d0e00d40eecde9e3ab80438698923a2620036c2fc33315ef95229e98571"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Tsunami"
		filetype = "executable"

	strings:
		$a = { 3E 20 3C 70 6F 72 74 3E 20 3C 72 65 66 6C 65 63 74 69 6F 6E 20 }

	condition:
		all of them
}
