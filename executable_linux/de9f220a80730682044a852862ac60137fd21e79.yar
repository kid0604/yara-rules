rule Linux_Hacktool_Flooder_3cbdfb1f
{
	meta:
		author = "Elastic Security"
		id = "3cbdfb1f-6c66-48be-931e-3ae609c46ff4"
		fingerprint = "c7f5d7641ea6e780bc3045181c929be73621acfe6aec4d157f6a9e0334ba7fb9"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Hacktool.Flooder"
		reference_sample = "bd40ac964f3ad2011841c7eb4bf7cab332d4d95191122e830ab031dc9511c079"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Hacktool.Flooder"
		filetype = "executable"

	strings:
		$a = { 5B 53 54 44 32 2E 43 20 42 59 20 53 54 41 43 4B 44 5D 20 53 }

	condition:
		all of them
}
