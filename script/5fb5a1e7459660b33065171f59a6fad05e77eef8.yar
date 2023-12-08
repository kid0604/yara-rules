rule WebShell_php_webshells_kral
{
	meta:
		description = "PHP Webshells Github Archive - file kral.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "4cd1d1a2fd448cecc605970e3a89f3c2e5c80dfc"
		os = "linux, windows, macos"
		filetype = "script"

	strings:
		$s1 = "$adres=gethostbyname($ip);" fullword
		$s3 = "curl_setopt($ch,CURLOPT_POSTFIELDS,\"domain=\".$site);" fullword
		$s4 = "$ekle=\"/index.php?option=com_user&view=reset&layout=confirm\";" fullword
		$s16 = "echo $son.' <br> <font color=\"green\">Access</font><br>';" fullword
		$s17 = "<p>kodlama by <a href=\"mailto:priv8coder@gmail.com\">BLaSTER</a><br /"
		$s20 = "<p><strong>Server listeleyici</strong><br />" fullword

	condition:
		2 of them
}
