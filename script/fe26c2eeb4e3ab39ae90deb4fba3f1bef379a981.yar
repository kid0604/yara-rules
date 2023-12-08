rule installer_alt_1
{
	meta:
		description = "Webshells Auto-generated - file installer.cmd"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "a507919ae701cf7e42fa441d3ad95f8f"
		os = "windows"
		filetype = "script"

	strings:
		$s0 = "Restore Old Vanquish"
		$s4 = "ReInstall Vanquish"

	condition:
		all of them
}
