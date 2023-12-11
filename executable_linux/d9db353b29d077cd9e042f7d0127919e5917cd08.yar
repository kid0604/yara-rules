rule Linux_Hacktool_Flooder_d710a5da
{
	meta:
		author = "Elastic Security"
		id = "d710a5da-26bf-4f6a-bf51-9cdac1f83aa3"
		fingerprint = "e673aa8785c7076f4cced9f12b284a2927b762fe1066aba8d6a5ace775f3480c"
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
		$a = { 74 24 48 8B 45 E0 48 83 C0 10 48 8B 08 48 8B 45 E0 48 83 C0 08 48 }

	condition:
		all of them
}
