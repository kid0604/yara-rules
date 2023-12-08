rule phpspy_2005_full_alt_1
{
	meta:
		description = "Webshells Auto-generated - file phpspy_2005_full.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "d1c69bb152645438440e6c903bac16b2"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s7 = "echo \"  <td align=\\\"center\\\" nowrap valign=\\\"top\\\"><a href=\\\"?downfile=\".urlenco"

	condition:
		all of them
}
