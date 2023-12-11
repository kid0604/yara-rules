rule webshell_SimAttacker_Vrsion_1_0_0_priv8_4_My_friend
{
	meta:
		description = "Web Shell - file SimAttacker - Vrsion 1.0.0 - priv8 4 My friend.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "089ff24d978aeff2b4b2869f0c7d38a3"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s2 = "echo \"<a href='?id=fm&fchmod=$dir$file'><span style='text-decoration: none'><fo"
		$s3 = "fputs ($fp ,\"\\n*********************************************\\nWelcome T0 Sim"

	condition:
		1 of them
}
