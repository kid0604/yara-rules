rule Linux_Hacktool_Bruteforce_66a14c03
{
	meta:
		author = "Elastic Security"
		id = "66a14c03-f4a3-4b24-a5db-5a9235334e37"
		fingerprint = "255c1a2e781ff7f330c09b3c82f08db110579f77ccef8780d03e9aa3eec86607"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Hacktool.Bruteforce"
		reference_sample = "a2d8e2c34ae95243477820583c0b00dfe3f475811d57ffb95a557a227f94cd55"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Hacktool.Bruteforce malware"
		filetype = "executable"

	strings:
		$a = { 48 8B 4C 24 08 78 3D 48 8B 44 24 30 48 29 C8 48 89 4D 08 48 89 }

	condition:
		all of them
}
