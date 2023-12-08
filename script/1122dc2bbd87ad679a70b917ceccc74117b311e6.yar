rule webshell_Safe_Mode_Bypass_PHP_4_4_2_and_PHP_5_1_2
{
	meta:
		description = "Web Shell - file Safe_Mode Bypass PHP 4.4.2 and PHP 5.1.2.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "49ad9117c96419c35987aaa7e2230f63"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "die(\"\\nWelcome.. By This script you can jump in the (Safe Mode=ON) .. Enjoy\\n"
		$s1 = "Mode Shell v1.0</font></span></a></font><font face=\"Webdings\" size=\"6\" color"

	condition:
		1 of them
}
