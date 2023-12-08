rule webshell_mysqlwebsh
{
	meta:
		description = "Web Shell - file mysqlwebsh.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "babfa76d11943a22484b3837f105fada"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s3 = " <TR><TD bgcolor=\"<? echo (!$CONNECT && $action == \"chparam\")?\"#660000\":\"#"

	condition:
		all of them
}
