rule WebShell_php_include_w_shell
{
	meta:
		description = "PHP Webshells Github Archive - file php-include-w-shell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "1a7f4868691410830ad954360950e37c582b0292"
		os = "linux"
		filetype = "script"

	strings:
		$s13 = "# dump variables (DEBUG SCRIPT) NEEDS MODIFINY FOR B64 STATUS!!" fullword
		$s17 = "\"phpshellapp\" => \"export TERM=xterm; bash -i\"," fullword
		$s19 = "else if($numhosts == 1) $strOutput .= \"On 1 host..\\n\";" fullword

	condition:
		1 of them
}
