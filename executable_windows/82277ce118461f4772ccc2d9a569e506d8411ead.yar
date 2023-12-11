import "pe"

rule antisb_sandboxie
{
	meta:
		author = "x0r"
		description = "Anti-Sandbox checks for Sandboxie"
		version = "0.1"
		os = "windows"
		filetype = "executable"

	strings:
		$f1 = "SbieDLL.dll" nocase

	condition:
		all of them
}
