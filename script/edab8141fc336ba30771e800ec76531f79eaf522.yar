rule phpjackal_php
{
	meta:
		description = "Semi-Auto-generated  - file phpjackal.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "ab230817bcc99acb9bdc0ec6d264d76f"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s3 = "$dl=$_REQUEST['downloaD'];"
		$s4 = "else shelL(\"perl.exe $name $port\");"

	condition:
		1 of them
}
