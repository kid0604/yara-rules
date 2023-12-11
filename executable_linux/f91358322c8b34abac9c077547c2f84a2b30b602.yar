rule Linux_Hacktool_Flooder_f434a3fb
{
	meta:
		author = "Elastic Security"
		id = "f434a3fb-e5fd-4749-8e53-fc6c80ee5406"
		fingerprint = "b74e55c56a063e14608f7e8f578cc3c74ec57954df39e63e49b60c0055725d51"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Hacktool.Flooder"
		reference_sample = "ba895a9c449bf9bf6c092df88b6d862a3e8ed4079ef795e5520cb163a45bcdb4"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Hacktool.Flooder"
		filetype = "executable"

	strings:
		$a = { C0 48 01 45 F8 48 83 45 E8 02 83 6D E4 01 83 7D E4 00 7F E3 48 8B }

	condition:
		all of them
}
