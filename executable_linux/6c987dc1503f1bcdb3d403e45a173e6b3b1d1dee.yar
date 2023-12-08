rule Linux_Cryptominer_Generic_97e9cebe
{
	meta:
		author = "Elastic Security"
		id = "97e9cebe-d30b-49f6-95f4-fd551e7a42e4"
		fingerprint = "61bef39d174d97897ac0820b624b1afbfe73206208db420ae40269967213ebed"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Generic"
		reference_sample = "b4ff62d92bd4d423379f26b37530776b3f4d927cc8a22bd9504ef6f457de4b7a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects generic Linux cryptominer"
		filetype = "executable"

	strings:
		$a = { 8B 04 25 28 00 00 00 48 89 44 24 58 31 C0 49 83 FF 3F 48 89 74 }

	condition:
		all of them
}
