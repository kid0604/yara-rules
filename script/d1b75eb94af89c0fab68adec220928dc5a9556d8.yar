rule Dx_php_php
{
	meta:
		description = "Semi-Auto-generated  - file Dx.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "9cfe372d49fe8bf2fac8e1c534153d9b"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "print \"\\n\".'Tip: to view the file \"as is\" - open the page in <a href=\"'.Dx"
		$s2 = "$DEF_PORTS=array (1=>'tcpmux (TCP Port Service Multiplexer)',2=>'Management Util"
		$s3 = "$ra44  = rand(1,99999);$sj98 = \"sh-$ra44\";$ml = \"$sd98\";$a5 = $_SERVER['HTTP"

	condition:
		1 of them
}
