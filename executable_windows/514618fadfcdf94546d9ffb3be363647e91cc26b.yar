rule bdcli100
{
	meta:
		description = "Webshells Auto-generated - file bdcli100.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "b12163ac53789fb4f62e4f17a8c2e028"
		os = "windows"
		filetype = "executable"

	strings:
		$s5 = "unable to connect to "
		$s8 = "backdoor is corrupted on "

	condition:
		all of them
}
