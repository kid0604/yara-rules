import "pe"

rule check_patchlevel
{
	meta:
		author = "x0r"
		description = "Check if hotfix are applied"
		version = "0.1"
		os = "windows"
		filetype = "executable"

	strings:
		$p1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Hotfix" nocase

	condition:
		any of them
}
