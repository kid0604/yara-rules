rule Linux_Trojan_Generic_c3d529a2
{
	meta:
		author = "Elastic Security"
		id = "c3d529a2-f2c7-41de-ba2a-2cbf2eb4222c"
		fingerprint = "72ef5b28489e01c3f2413b9a907cda544fc3f60e00451382e239b55ec982f187"
		creation_date = "2022-09-12"
		last_modified = "2022-10-18"
		threat_name = "Linux.Trojan.Generic"
		reference_sample = "b46135ae52db6399b680e5c53f891d101228de5cd6c06b6ae115e4a763a5fb22"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Generic with fingerprint c3d529a2"
		filetype = "executable"

	strings:
		$a = { 1C 31 C0 5B 5E 5F 5D C3 8B 1C 24 C3 8D 64 24 04 53 8B DA 5B }

	condition:
		all of them
}
