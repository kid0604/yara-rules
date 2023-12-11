rule Sincap_php_php
{
	meta:
		description = "Semi-Auto-generated  - file Sincap.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "b68b90ff6012a103e57d141ed38a7ee9"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "$baglan=fopen(\"/tmp/$ekinci\",'r');"
		$s2 = "$tampon4=$tampon3-1"
		$s3 = "@aventgrup.net"

	condition:
		2 of them
}
