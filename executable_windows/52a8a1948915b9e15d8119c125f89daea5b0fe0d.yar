rule apt_equation_exploitlib_mutexes_alt_1
{
	meta:
		copyright = "Kaspersky Lab"
		description = "Rule to detect Equation group's Exploitation library http://goo.gl/ivt8EW"
		version = "1.0"
		date = "2016-02-15"
		modified = "2023-01-27"
		reference = "http://securelist.com/blog/research/68750/equation-the-death-star-of-malware-galaxy/"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "prkMtx" wide
		$a2 = "cnFormSyncExFBC" wide
		$a3 = "cnFormVoidFBC" wide
		$a4 = "cnFormSyncExFBC"
		$a5 = "cnFormVoidFBC"

	condition:
		uint16(0)==0x5A4D and any of ($a*)
}
