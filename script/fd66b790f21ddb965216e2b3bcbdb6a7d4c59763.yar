rule webshell_php_moon
{
	meta:
		description = "Web Shell - file moon.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "2a2b1b783d3a2fa9a50b1496afa6e356"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s2 = "echo '<option value=\"create function backshell returns string soname"
		$s3 = "echo      \"<input name='p' type='text' size='27' value='\".dirname(_FILE_).\""
		$s8 = "echo '<option value=\"select cmdshell(\\'net user "

	condition:
		2 of them
}
