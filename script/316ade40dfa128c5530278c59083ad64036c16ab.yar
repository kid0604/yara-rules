rule r57shell_alt_1
{
	meta:
		description = "Webshells Auto-generated - file r57shell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "8023394542cddf8aee5dec6072ed02b5"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s11 = " $_POST['cmd']=\"echo \\\"Now script try connect to"

	condition:
		all of them
}
