import "pe"

rule HKTL_shellpop_Telnet_TCP
{
	meta:
		description = "Detects malicious telnet shell"
		author = "Tobias Michalski"
		reference = "https://github.com/0x00-0x00/ShellPop"
		date = "2018-05-18"
		hash1 = "cf5232bae0364606361adafab32f19cf56764a9d3aef94890dda9f7fcd684a0e"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$x1 = "if [ -e /tmp/f ]; then rm /tmp/f;" ascii
		$x2 = "0</tmp/f|/bin/bash 1>/tmp/f" fullword ascii

	condition:
		filesize <3KB and 1 of them
}
