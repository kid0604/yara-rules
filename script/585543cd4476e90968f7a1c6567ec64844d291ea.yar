rule MySQL_Web_Interface_Version_0_8_php
{
	meta:
		description = "Semi-Auto-generated  - file MySQL Web Interface Version 0.8.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "36d4f34d0a22080f47bb1cb94107c60f"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "SooMin Kim"
		$s1 = "http://popeye.snu.ac.kr/~smkim/mysql"
		$s2 = "href='$PHP_SELF?action=dropField&dbname=$dbname&tablename=$tablename"
		$s3 = "<th>Type</th><th>&nbspM&nbsp</th><th>&nbspD&nbsp</th><th>unsigned</th><th>zerofi"

	condition:
		2 of them
}
