import "pe"

rule antisb_cwsandbox
{
	meta:
		author = "x0r"
		description = "Anti-Sandbox checks for CWSandbox"
		version = "0.1"
		os = "windows"
		filetype = "executable"

	strings:
		$p1 = "Software\\Microsoft\\Windows\\CurrentVersion" nocase
		$s1 = "76487-644-3177037-23510"

	condition:
		all of them
}
