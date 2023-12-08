import "pe"

rule antisb_joesanbox
{
	meta:
		author = "x0r"
		description = "Anti-Sandbox checks for Joe Sandbox"
		version = "0.1"
		os = "windows"
		filetype = "executable"

	strings:
		$p1 = "Software\\Microsoft\\Windows\\CurrentVersion" nocase
		$c1 = "RegQueryValue"
		$s1 = "55274-640-2673064-23950"

	condition:
		all of them
}
