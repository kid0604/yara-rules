rule WebShell_PHANTASMA
{
	meta:
		description = "PHP Webshells Github Archive - file PHANTASMA.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "cd12d42abf854cd34ff9e93a80d464620af6d75e"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s12 = "\"    printf(\\\"Usage: %s [Host] <port>\\\\n\\\", argv[0]);\\n\" ." fullword
		$s15 = "if ($portscan != \"\") {" fullword
		$s16 = "echo \"<br>Banner: $get <br><br>\";" fullword
		$s20 = "$dono = get_current_user( );" fullword

	condition:
		3 of them
}
