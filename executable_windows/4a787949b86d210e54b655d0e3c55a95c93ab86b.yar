rule byshell063_ntboot_2
{
	meta:
		description = "Webshells Auto-generated - file ntboot.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "cb9eb5a6ff327f4d6c46aacbbe9dda9d"
		os = "windows"
		filetype = "executable"

	strings:
		$s6 = "OK,job was done,cuz we have localsystem & SE_DEBUG_NAME:)"

	condition:
		all of them
}
