rule Linux_Virus_Gmon_e544d891
{
	meta:
		author = "Elastic Security"
		id = "e544d891-3f6d-4da2-be86-e4ab58c66465"
		fingerprint = "269f0777f846f9fc8fe56ea7436bddb155cde8c9a4bf9070f46db0081caef718"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Virus.Gmon"
		reference_sample = "d0fe377664aa0bc0d1fd3a307650f211dd3ef2e2f04597abee465e836e6a6f32"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Virus.Gmon"
		filetype = "executable"

	strings:
		$a = { E5 53 51 52 8B 44 24 14 8B 5C 24 18 8B 4C 24 1C 8B 54 24 20 }

	condition:
		all of them
}
