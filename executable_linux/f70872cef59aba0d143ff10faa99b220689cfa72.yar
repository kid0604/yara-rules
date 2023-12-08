rule Linux_Hacktool_Flooder_825b6808
{
	meta:
		author = "Elastic Security"
		id = "825b6808-9b23-4a55-9f26-a34cab6ea92b"
		fingerprint = "e2db86e614b9bc0de06daf626abe652cc6385cca8ba96a2f2e394cf82be7a29b"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Hacktool.Flooder"
		reference_sample = "7db9a0760dd16e23cb299559a0e31a431b836a105d5309a9880fa4b821937659"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Hacktool.Flooder"
		filetype = "executable"

	strings:
		$a = { 10 83 EC 04 8B 45 E4 FF 70 0C 8D 45 E8 83 C0 04 50 8B 45 E4 8B }

	condition:
		all of them
}
