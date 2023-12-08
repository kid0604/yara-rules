rule Linux_Cryptominer_Stak_52dc7af3
{
	meta:
		author = "Elastic Security"
		id = "52dc7af3-a742-4307-a5ae-c929fede1cc4"
		fingerprint = "330262703d3fcdd8b2c217db552f07e19f5df4d6bf115bfa291bb1c7f802ad97"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Stak"
		reference_sample = "a9c14b51f95d0c368bf90fb10e7d821a2fbcc79df32fd9f068a7fc053cbd7e83"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Cryptominer.Stak malware"
		filetype = "executable"

	strings:
		$a = { F9 48 89 D3 4D 8B 74 24 20 48 8D 41 01 4C 29 FB 4C 8D 6B 10 48 }

	condition:
		all of them
}
