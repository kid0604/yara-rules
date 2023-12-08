import "pe"

rule disable_registry
{
	meta:
		author = "x0r"
		description = "Disable Registry editor"
		version = "0.1"
		os = "windows"
		filetype = "executable"

	strings:
		$p1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" nocase
		$c1 = "RegSetValue"
		$r1 = "DisableRegistryTools"
		$r2 = "DisableRegedit"

	condition:
		1 of ($p*) and $c1 and 1 of ($r*)
}
