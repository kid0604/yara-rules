rule EQGRP_eligiblebombshell_generic
{
	meta:
		description = "EQGRP Toolset Firewall - from files eligiblebombshell_1.2.0.1.py, eligiblebombshell_1.2.0.1.py"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		super_rule = 1
		hash1 = "dd0e3ae6e1039a755bf6cb28bf726b4d6ab4a1da2392ba66d114a43a55491eb1"
		hash2 = "dd0e3ae6e1039a755bf6cb28bf726b4d6ab4a1da2392ba66d114a43a55491eb1"
		os = "windows,linux"
		filetype = "script"

	strings:
		$s1 = "logging.error(\"       Perhaps you should run with --scan?\")" fullword ascii
		$s2 = "logging.error(\"ERROR: No entry for ETag [%s] in %s.\" %" fullword ascii
		$s3 = "\"be supplied\")" fullword ascii

	condition:
		( filesize <70KB and 2 of ($s*)) or ( all of them )
}
