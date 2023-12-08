rule WebShell_Safe_Mode_Bypass_PHP_4_4_2_and_PHP_5_1_2
{
	meta:
		description = "PHP Webshells Github Archive - file Safe_Mode_Bypass_PHP_4.4.2_and_PHP_5.1.2.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "db076b7c80d2a5279cab2578aa19cb18aea92832"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "<option value=\"/etc/passwd\">Get /etc/passwd</option>" fullword
		$s6 = "by PHP Emperor<xb5@hotmail.com>" fullword
		$s9 = "\".htmlspecialchars($file).\" has been already loaded. PHP Emperor <xb5@hotmail."
		$s11 = "die(\"<FONT COLOR=\\\"RED\\\"><CENTER>Sorry... File" fullword
		$s15 = "if(empty($_GET['file'])){" fullword
		$s16 = "echo \"<head><title>Safe Mode Shell</title></head>\"; " fullword

	condition:
		3 of them
}
