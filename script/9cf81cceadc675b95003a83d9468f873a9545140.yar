import "pe"

rule HKTL_shellpop_PHP_TCP
{
	meta:
		description = "Detects malicious PHP shell"
		author = "Tobias Michalski"
		reference = "https://github.com/0x00-0x00/ShellPop"
		date = "2018-05-18"
		hash1 = "0412e1ab9c672abecb3979a401f67d35a4a830c65f34bdee3f87e87d060f0290"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$x1 = "php -r \"\\$sock=fsockopen" ascii
		$x2 = ";exec('/bin/sh -i <&3 >&3 2>&3');\"" ascii

	condition:
		filesize <3KB and all of them
}
