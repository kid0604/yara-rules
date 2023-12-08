rule csh_php_php
{
	meta:
		description = "Semi-Auto-generated  - file csh.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "194a9d3f3eac8bc56d9a7c55c016af96"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = ".::[c0derz]::. web-shell"
		$s1 = "http://c0derz.org.ua"
		$s2 = "vint21h@c0derz.org.ua"
		$s3 = "$name='63a9f0ea7bb98050796b649e85481845';//root"

	condition:
		1 of them
}
