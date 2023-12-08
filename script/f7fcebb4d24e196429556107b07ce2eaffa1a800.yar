rule WebShell_ftpsearch
{
	meta:
		description = "PHP Webshells Github Archive - file ftpsearch.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "c945f597552ccb8c0309ad6d2831c8cabdf4e2d6"
		os = "linux"
		filetype = "script"

	strings:
		$s0 = "echo \"[-] Error : coudn't read /etc/passwd\";" fullword
		$s9 = "@$ftp=ftp_connect('127.0.0.1');" fullword
		$s12 = "echo \"<title>Edited By KingDefacer</title><body>\";" fullword
		$s19 = "echo \"[+] Founded \".sizeof($users).\" entrys in /etc/passwd\\n\";" fullword

	condition:
		2 of them
}
