rule Linux_Hacktool_Flooder_e63396f4
{
	meta:
		author = "Elastic Security"
		id = "e63396f4-a297-4d99-b341-34cb22498078"
		fingerprint = "269285d03ea1a3b41ff134ab2cf5e22502626c72401b83add6c1e165f4dd83f8"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Hacktool.Flooder"
		reference_sample = "913e6d2538bd7eed3a8f3d958cf445fe11c5c299a70e5385e0df6a9b2f638323"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Hacktool.Flooder"
		filetype = "executable"

	strings:
		$a = { 02 83 45 FC 01 81 7D FC FF 0F 00 00 7E ?? 90 }

	condition:
		all of them
}
