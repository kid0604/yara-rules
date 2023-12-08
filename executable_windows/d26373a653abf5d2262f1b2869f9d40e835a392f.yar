import "pe"

rule apt_equation_exploitlib_mutexes
{
	meta:
		copyright = "Kaspersky Lab"
		description = "Rule to detect Equation group's Exploitation library http://goo.gl/ivt8EW"
		version = "1.0"
		last_modified = "2015-02-16"
		reference = "http://securelist.com/blog/research/68750/equation-the-death-star-of-malware-galaxy/"
		os = "windows"
		filetype = "executable"

	strings:
		$mz = "MZ"
		$a1 = "prkMtx" wide
		$a2 = "cnFormSyncExFBC" wide
		$a3 = "cnFormVoidFBC" wide
		$a4 = "cnFormSyncExFBC"
		$a5 = "cnFormVoidFBC"

	condition:
		(($mz at 0) and any of ($a*))
}
