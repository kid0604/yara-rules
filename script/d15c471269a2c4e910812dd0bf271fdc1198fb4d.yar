rule c99shell_alt_1
{
	meta:
		description = "Webshells Auto-generated - file c99shell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "90b86a9c63e2cd346fe07cea23fbfc56"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "<br />Input&nbsp;URL:&nbsp;&lt;input&nbsp;name=\\\"uploadurl\\\"&nbsp;type=\\\"text\\\"&"

	condition:
		all of them
}
