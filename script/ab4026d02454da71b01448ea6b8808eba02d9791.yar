rule small_php_php
{
	meta:
		description = "Semi-Auto-generated  - file small.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "fcee6226d09d150bfa5f103bee61fbde"
		os = "windows,linux,macos"
		filetype = "script"

	strings:
		$s1 = "$pass='abcdef1234567890abcdef1234567890';" fullword
		$s2 = "eval(gzinflate(base64_decode('FJzHkqPatkU/550IGnjXxHvv6bzAe0iE5+svFVGtKqXMZq05x1"
		$s4 = "@ini_set('error_log',NULL);" fullword

	condition:
		2 of them
}
