rule Linux_Exploit_Lotoor_f2f8eb6b
{
	meta:
		author = "Elastic Security"
		id = "f2f8eb6b-1fc3-4fca-b58d-d71ad932e1a7"
		fingerprint = "881e2cd5b644c2511306b3670320224810de369971278516f7562076226fa5b7"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.Lotoor"
		reference_sample = "01721b9c024ca943f42c402a57f45bd4c77203a604c5c2cd26e5670df76a95b2"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the Linux.Exploit.Lotoor malware"
		filetype = "executable"

	strings:
		$a = { 24 14 40 00 00 00 EB 38 8B 44 24 14 48 98 83 E0 3F 48 85 C0 }

	condition:
		all of them
}
