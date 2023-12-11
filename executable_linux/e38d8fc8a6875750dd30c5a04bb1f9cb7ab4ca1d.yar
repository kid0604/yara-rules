rule Linux_Trojan_Tsunami_0e52c842
{
	meta:
		author = "Elastic Security"
		id = "0e52c842-f65e-4c77-8081-ae2f160e35f4"
		fingerprint = "70fdfb7aa5d1eff98e4e216e7a60ed1ba4d75ed1f47a57bf40eeaf35a92c88e4"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Tsunami"
		reference_sample = "cf1ca1d824c8687e87a5b0275a0e39fa101442b4bbf470859ddda9982f9b3417"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Tsunami with ID 0e52c842"
		filetype = "executable"

	strings:
		$a = { 55 48 89 E5 53 48 83 EC 38 89 7D E4 48 89 75 D8 89 55 D4 48 89 }

	condition:
		all of them
}
