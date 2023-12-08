rule webshell_Mysql_interface_v1_0
{
	meta:
		description = "Web Shell - file Mysql interface v1.0.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "a12fc0a3d31e2f89727b9678148cd487"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "echo \"<td><a href='$PHP_SELF?action=dropDB&dbname=$dbname' onClick=\\\"return"

	condition:
		all of them
}
