rule Linux_Cryptominer_Generic_7ef74003
{
	meta:
		author = "Elastic Security"
		id = "7ef74003-cd1f-4f2f-9c96-4dbcabaa36e4"
		fingerprint = "187fd82b91ae6eadc786cadac75de5d919a2b8a592037a5bf8da2efa2539f507"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Generic"
		reference_sample = "a172cfecdec8ebd365603ae094a16e247846fdbb47ba7fd79564091b7e8942a0"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Cryptominer.Generic"
		filetype = "executable"

	strings:
		$a = { 41 56 45 31 F6 41 55 49 89 F5 41 54 44 8D 67 01 55 4D 63 E4 53 49 C1 }

	condition:
		all of them
}
