rule WebShell_php_webshells_lolipop
{
	meta:
		description = "PHP Webshells Github Archive - file lolipop.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "86f23baabb90c93465e6851e40104ded5a5164cb"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s3 = "$commander = $_POST['commander']; " fullword
		$s9 = "$sourcego = $_POST['sourcego']; " fullword
		$s20 = "$result = mysql_query($loli12) or die (mysql_error()); " fullword

	condition:
		all of them
}
