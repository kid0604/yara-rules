rule webshell_Liz0ziM_Private_Safe_Mode_Command_Execuriton_Bypass_Exploit
{
	meta:
		description = "Web Shell - file Liz0ziM Private Safe Mode Command Execuriton Bypass Exploit.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "c6eeacbe779518ea78b8f7ed5f63fc11"
		os = "linux"
		filetype = "script"

	strings:
		$s1 = "<option value=\"cat /etc/passwd\">/etc/passwd</option>" fullword

	condition:
		all of them
}
