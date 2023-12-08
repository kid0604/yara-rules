rule Linux_Hacktool_Flooder_1bf0e994
{
	meta:
		author = "Elastic Security"
		id = "1bf0e994-2648-4dbb-9b9c-b86b9a347700"
		fingerprint = "1f844c349b47dd49a75d50e43b6664e9d2b95c362efb730448934788b6bddb79"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Hacktool.Flooder"
		reference_sample = "1ea2dc13eec0d7a8ec20307f5afac8e9344d827a6037bb96a54ad7b12f65b59c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Hacktool.Flooder"
		filetype = "executable"

	strings:
		$a = { 05 88 10 48 8B 45 B8 0F B6 10 83 E2 0F 83 CA 40 88 10 48 8B }

	condition:
		all of them
}
