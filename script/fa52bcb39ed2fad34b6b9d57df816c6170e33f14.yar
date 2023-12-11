rule iMHaPFtp_alt_1
{
	meta:
		description = "Webshells Auto-generated - file iMHaPFtp.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "12911b73bc6a5d313b494102abcf5c57"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "echo \"\\t<th class=\\\"permission_header\\\"><a href=\\\"$self?{$d}sort=permission$r\\\">"

	condition:
		all of them
}
