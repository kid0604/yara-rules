rule webshell_PHP_G5
{
	meta:
		description = "Web Shell - file G5.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "95b4a56140a650c74ed2ec36f08d757f"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s3 = "echo \"Hacking Mode?<br><select name='htype'><option >--------SELECT--------</op"

	condition:
		all of them
}
