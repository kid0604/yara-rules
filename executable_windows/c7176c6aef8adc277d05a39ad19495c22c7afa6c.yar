import "pe"

rule antisb_threatExpert
{
	meta:
		author = "x0r"
		description = "Anti-Sandbox checks for ThreatExpert"
		version = "0.1"
		os = "windows"
		filetype = "executable"

	strings:
		$f1 = "dbghelp.dll" nocase

	condition:
		all of them
}
