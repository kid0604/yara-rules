rule FeliksPack3___PHP_Shells_xIShell
{
	meta:
		description = "Webshells Auto-generated - file xIShell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "997c8437c0621b4b753a546a53a88674"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s3 = "if (!$nix) { $xid = implode(explode(\"\\\\\",$xid),\"\\\\\\\\\");}echo (\"<td><a href='Java"

	condition:
		all of them
}
