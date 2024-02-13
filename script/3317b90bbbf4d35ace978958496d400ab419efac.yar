rule malware_ruoji_phpwebshell
{
	meta:
		description = "ruoji webshell"
		author = "JPCERT/CC Incident Response Group"
		hash = "8a389390a9ce4aba962e752218c5e9ab879b58280049a5e02b9143e750265064"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "zxcszxctzxcrzxc_zxcrzxcezxc" ascii
		$s2 = "<?php if ($_COOKIE[" ascii
		$s3 = "'] !== $_GET['" ascii
		$s4 = "'] && @md5($_GET['" ascii
		$s5 = "']) === @md5($_GET['" ascii

	condition:
		4 of them
}
