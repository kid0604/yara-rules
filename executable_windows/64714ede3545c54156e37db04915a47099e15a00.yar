rule hkshell_hkrmv
{
	meta:
		description = "Webshells Auto-generated - file hkrmv.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "bd3a0b7a6b5536f8d96f50956560e9bf"
		os = "windows"
		filetype = "executable"

	strings:
		$s5 = "/THUMBPOSITION7"
		$s6 = "\\EvilBlade\\"

	condition:
		all of them
}
