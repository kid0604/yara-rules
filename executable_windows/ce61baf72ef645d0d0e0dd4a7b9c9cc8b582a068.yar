import "pe"

rule win_hook
{
	meta:
		author = "x0r"
		description = "Affect hook table"
		version = "0.1"
		os = "windows"
		filetype = "executable"

	strings:
		$f1 = "user32.dll" nocase
		$c1 = "UnhookWindowsHookEx"
		$c2 = "SetWindowsHookExA"
		$c3 = "CallNextHookEx"

	condition:
		$f1 and 1 of ($c*)
}
