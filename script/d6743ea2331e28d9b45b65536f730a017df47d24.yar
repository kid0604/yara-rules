rule w3d_php_php
{
	meta:
		description = "Semi-Auto-generated  - file w3d.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "987f66b29bfb209a0b4f097f84f57c3b"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "W3D Shell"
		$s1 = "By: Warpboy"
		$s2 = "No Query Executed"

	condition:
		2 of them
}
