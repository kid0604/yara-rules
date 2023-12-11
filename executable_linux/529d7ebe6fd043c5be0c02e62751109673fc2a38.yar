rule Linux_Exploit_Lotoor_e2d5fad8
{
	meta:
		author = "Elastic Security"
		id = "e2d5fad8-45b6-4d65-826d-b909230e2b69"
		fingerprint = "ec64f2c3ca5ec2bfc2146159dab3258e389be5962bdddf4c6db5975cc730a231"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.Lotoor"
		reference_sample = "7e54e57db3de32555c15e529c04b35f52d75af630e45b5f8d6c21149866b6929"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the Linux.Exploit.Lotoor malware"
		filetype = "executable"

	strings:
		$a = { 8B 45 E4 8B 00 89 45 E8 8B 45 E8 8B 00 85 C0 75 08 8B 45 E8 89 }

	condition:
		all of them
}
