rule Linux_Trojan_Gafgyt_9a62845f
{
	meta:
		author = "Elastic Security"
		id = "9a62845f-6311-49ae-beac-f446b2909d9c"
		fingerprint = "2ccc813c5efed35308eb2422239b5b83d051eca64b7c785e66d602b13f8bd9b4"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Gafgyt"
		reference_sample = "f67f8566beab9d7494350923aceb0e76cd28173bdf2c4256e9d45eff7fc8cb41"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt variant with ID 9a62845f"
		filetype = "executable"

	strings:
		$a = { 10 83 F8 20 7F 1E 83 7D 08 07 75 33 8B 45 0C 83 C0 18 8B 00 83 }

	condition:
		all of them
}
