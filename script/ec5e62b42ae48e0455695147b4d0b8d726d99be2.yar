rule WebShell_CasuS_1_5
{
	meta:
		description = "PHP Webshells Github Archive - file CasuS 1.5.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "7eee8882ad9b940407acc0146db018c302696341"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s2 = "<font size='+1'color='#0000FF'><u>CasuS 1.5'in URL'si</u>: http://$HTTP_HO"
		$s8 = "$fonk_kap = get_cfg_var(\"fonksiyonlary_kapat\");" fullword
		$s18 = "if (file_exists(\"F:\\\\\")){" fullword

	condition:
		1 of them
}
