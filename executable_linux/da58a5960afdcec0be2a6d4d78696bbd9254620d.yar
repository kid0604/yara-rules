rule Linux_Exploit_Cornelgen_03ee53d3
{
	meta:
		author = "Elastic Security"
		id = "03ee53d3-4f03-4c5e-9187-45e0e33584b4"
		fingerprint = "f2a8ecfffb0328c309a3a5db7e62fae56bf168806a1db961a57effdebba7645e"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.Cornelgen"
		reference_sample = "711eafd09d4e5433be142d54db153993ee55b6c53779d8ec7e76ca534b4f81a5"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Linux.Exploit.Cornelgen is a Linux exploit rule targeting x86 architecture"
		filetype = "executable"

	strings:
		$a = { C9 B0 27 CD 80 31 C0 B0 3D CD 80 31 C0 8D 5E 02 }

	condition:
		all of them
}
