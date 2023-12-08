rule DllInjection
{
	meta:
		description = "Webshells Auto-generated - file DllInjection.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "a7b92283a5102886ab8aee2bc5c8d718"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "\\BDoor\\DllInjecti"

	condition:
		all of them
}
