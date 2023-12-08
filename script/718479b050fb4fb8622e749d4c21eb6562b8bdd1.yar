rule md5_9b59cb5b557e46e1487ef891cedaccf7
{
	meta:
		description = "Detects a file with specific MD5 hash containing a JPG header and PHP code"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$jpg = { FF D8 FF E0 ?? ?? 4A 46 49 46 00 01 }
		$php = "<?php"

	condition:
		($jpg at 0) and $php
}
