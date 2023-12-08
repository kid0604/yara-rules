rule webshell_metaslsoft
{
	meta:
		description = "Web Shell - file metaslsoft.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "aa328ed1476f4a10c0bcc2dde4461789"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s7 = "$buff .= \"<tr><td><a href=\\\"?d=\".$pwd.\"\\\">[ $folder ]</a></td><td>LINK</t"

	condition:
		all of them
}
