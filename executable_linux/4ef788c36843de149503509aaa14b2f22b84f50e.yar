rule Linux_Exploit_Local_9ace9649
{
	meta:
		author = "Elastic Security"
		id = "9ace9649-c74a-4b27-a147-d14123104c0a"
		fingerprint = "2e526d7ec47a30c7683725c2d2c3db0a8267630bb0f270599325d50227f6ae29"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.Local"
		reference_sample = "b38869605521531153cfd8077f05e0d6b52dca0fffbc627a4d5eaa84855a491c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux local exploit"
		filetype = "executable"

	strings:
		$a = { 31 C0 31 DB 31 C9 B0 46 CD 80 31 C0 50 68 2F }

	condition:
		all of them
}
