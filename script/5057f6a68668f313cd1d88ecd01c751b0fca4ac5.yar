rule zacosmall_php
{
	meta:
		description = "Semi-Auto-generated  - file zacosmall.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "5295ee8dc2f5fd416be442548d68f7a6"
		os = "windows,linux,macos"
		filetype = "script"

	strings:
		$s0 = "rand(1,99999);$sj98"
		$s1 = "$dump_file.='`'.$rows2[0].'`"
		$s3 = "filename=\\\"dump_{$db_dump}_${table_d"

	condition:
		2 of them
}
