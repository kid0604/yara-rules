rule WebShell_Liz0ziM_Private_Safe_Mode_Command_Execuriton_Bypass_Exploit
{
	meta:
		description = "PHP Webshells Github Archive - file Liz0ziM Private Safe Mode Command Execuriton Bypass Exploit.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "b2b797707e09c12ff5e632af84b394ad41a46fa4"
		os = "linux"
		filetype = "script"

	strings:
		$s4 = "$liz0zim=shell_exec($_POST[liz0]); " fullword
		$s6 = "$liz0=shell_exec($_POST[baba]); " fullword
		$s9 = "echo \"<b><font color=blue>Liz0ziM Private Safe Mode Command Execuriton Bypass E"
		$s12 = " :=) :</font><select size=\"1\" name=\"liz0\">" fullword
		$s13 = "<option value=\"cat /etc/passwd\">/etc/passwd</option>" fullword

	condition:
		1 of them
}
