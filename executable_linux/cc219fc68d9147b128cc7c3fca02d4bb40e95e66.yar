rule Linux_Rootkit_Generic_f07bcabe
{
	meta:
		author = "Elastic Security"
		id = "f07bcabe-f91e-4872-8677-dee6307e79d0"
		fingerprint = "7335426e705383ff6f62299943a139390b83ce2af4cbfc145cfe78c0f0015a26"
		creation_date = "2024-12-02"
		last_modified = "2024-12-09"
		threat_name = "Linux.Rootkit.Generic"
		severity = 100
		arch_context = "x86, arm64"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects a generic Linux rootkit"
		filetype = "executable"

	strings:
		$str1 = "fh_install_hook"
		$str2 = "fh_remove_hook"
		$str3 = "fh_resolve_hook_address"

	condition:
		2 of them
}
