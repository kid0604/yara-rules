rule Linux_Trojan_Xorddos_61c88137
{
	meta:
		author = "Elastic Security"
		id = "61c88137-02f6-4339-b8fc-04c72a5023aa"
		fingerprint = "c09b31424a54e485fe5f89b4ab0a008df6e563a75191f19de12113890a4faa39"
		creation_date = "2022-09-12"
		last_modified = "2022-10-18"
		threat_name = "Linux.Trojan.Xorddos"
		reference_sample = "479ef38fa00bb13a3aa8448aa4a4434613c6729975e193eec29fc5047f339111"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Xorddos"
		filetype = "executable"

	strings:
		$a = { 24 8B C1 8B 0C 24 8D 64 24 FC 89 0C 24 8B 4D E8 87 0C 24 96 8D 64 }

	condition:
		all of them
}
