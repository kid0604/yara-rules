rule cyberlords_sql_php_php
{
	meta:
		description = "Semi-Auto-generated  - file cyberlords_sql.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "03b06b4183cb9947ccda2c3d636406d4"
		os = "windows,linux,macos"
		filetype = "script"

	strings:
		$s0 = "Coded by n0 [nZer0]"
		$s1 = " www.cyberlords.net"
		$s2 = "U29mdHdhcmUAQWRvYmUgSW1hZ2VSZWFkeXHJZTwAAAAMUExURf///wAAAJmZzAAAACJoURkAAAAE"
		$s3 = "return \"<BR>Dump error! Can't write to \".htmlspecialchars($file);"

	condition:
		1 of them
}
