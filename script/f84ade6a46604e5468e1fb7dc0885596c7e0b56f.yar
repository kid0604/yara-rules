rule backupsql_php_often_with_c99shell
{
	meta:
		description = "Semi-Auto-generated  - file backupsql.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "ab1a06ab1a1fe94e3f3b7f80eedbc12f"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s2 = "//$message.= \"--{$mime_boundary}\\n\" .\"Content-Type: {$fileatt_type};\\n\" ."
		$s4 = "$ftpconnect = \"ncftpput -u $ftp_user_name -p $ftp_user_pass -d debsender_ftplog"

	condition:
		all of them
}
