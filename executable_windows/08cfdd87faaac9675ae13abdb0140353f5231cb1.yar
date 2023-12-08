import "pe"

rule antivm_virtualbox
{
	meta:
		author = "x0r"
		description = "AntiVM checks for VirtualBox"
		version = "0.1"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "VBoxService.exe" nocase

	condition:
		any of them
}
