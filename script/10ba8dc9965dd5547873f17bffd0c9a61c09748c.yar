rule PM_Email_Sent_By_PHP_Script
{
	meta:
		description = "Detects emails sent by PHP script"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$php1 = "X-PHP-Script" fullword
		$php2 = "X-PHP-Originating-Script" fullword
		$php3 = "/usr/bin/php" fullword

	condition:
		any of them
}
