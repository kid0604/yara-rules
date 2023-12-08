import "pe"

rule HKTL_shellpop_netcat
{
	meta:
		description = "Detects suspcious netcat shellpop"
		author = "Tobias Michalski"
		reference = "https://github.com/0x00-0x00/ShellPop"
		date = "2018-05-18"
		hash1 = "98e3324f4c096bb1e5533114249a9e5c43c7913afa3070488b16d5b209e015ee"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "if [ -e /tmp/f ]; then rm /tmp/f;" ascii
		$s2 = "fi;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc" ascii
		$s4 = "mknod /tmp/f p && nc" ascii
		$s5 = "</tmp/f|/bin/bash 1>/tmp/f" ascii

	condition:
		filesize <2KB and 1 of them
}
