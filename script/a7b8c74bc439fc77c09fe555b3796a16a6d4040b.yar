rule WebShell_Generic_PHP_10
{
	meta:
		description = "PHP Webshells Github Archive - from files Cyber Shell.php, cybershell.php, Cyber Shell (v 1.0).php, PHPRemoteView.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		super_rule = 1
		hash0 = "ef7f7c45d26614cea597f2f8e64a85d54630fe38"
		hash1 = "cabf47b96e3b2c46248f075bdbc46197db28a25f"
		hash2 = "9e165d4ed95e0501cd9a90155ac60546eb5b1076"
		hash3 = "7d5b54c7cab6b82fb7d131d7bbb989fd53cb1b57"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s2 = "$world[\"execute\"] = ($world['execute']=='x') ? 't' : 'T'; " fullword
		$s6 = "$owner[\"write\"] = ($mode & 00200) ? 'w' : '-'; " fullword
		$s11 = "$world[\"execute\"] = ($mode & 00001) ? 'x' : '-'; " fullword
		$s12 = "else if( $mode & 0xA000 ) " fullword
		$s17 = "$s=sprintf(\"%1s\", $type); " fullword
		$s20 = "font-size: 8pt;" fullword

	condition:
		all of them
}
