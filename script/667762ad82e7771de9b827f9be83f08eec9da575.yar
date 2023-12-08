rule sh_php_php_alt_1
{
	meta:
		description = "Semi-Auto-generated  - file sh.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "330af9337ae51d0bac175ba7076d6299"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "$ar_file=array('/etc/passwd','/etc/shadow','/etc/master.passwd','/etc/fstab','/e"
		$s2 = "Show <input type=text size=5 value=\".((isset($_POST['br_st']))?$_POST['br_st']:"

	condition:
		1 of them
}
