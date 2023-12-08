rule WebShell_NTDaddy_v1_9
{
	meta:
		description = "PHP Webshells Github Archive - file NTDaddy v1.9.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "79519aa407fff72b7510c6a63c877f2e07d7554b"
		os = "windows,linux"
		filetype = "script"

	strings:
		$s2 = "|     -obzerve : mr_o@ihateclowns.com |" fullword
		$s6 = "szTempFile = \"C:\\\" & oFileSys.GetTempName( )" fullword
		$s13 = "<form action=ntdaddy.asp method=post>" fullword
		$s17 = "response.write(\"<ERROR: THIS IS NOT A TEXT FILE>\")" fullword

	condition:
		2 of them
}
