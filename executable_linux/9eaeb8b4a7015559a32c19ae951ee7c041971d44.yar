rule Linux_Hacktool_Flooder_7026f674
{
	meta:
		author = "Elastic Security"
		id = "7026f674-83b7-432b-9197-2d71abdb9579"
		fingerprint = "acf93628ecbda544c6c5d88388ac85bb2755c71544a0980ee1b2854c6bdb7c77"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Hacktool.Flooder"
		reference_sample = "b7a77ebb66664c54d01a57abed5bb034ef2933a9590b595bba0566938b099438"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Hacktool.Flooder"
		filetype = "executable"

	strings:
		$a = { 08 1E 77 DA 00 43 6F 75 6C 64 20 6E 6F 74 20 6F 70 65 6E 20 }

	condition:
		all of them
}
