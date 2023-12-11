import "pe"

rule SUSP_shellpop_Bash
{
	meta:
		description = "Detects susupicious bash command"
		author = "Tobias Michalski"
		reference = "https://github.com/0x00-0x00/ShellPop"
		date = "2018-05-18"
		hash1 = "36fad575a8bc459d0c2e3ad626e97d5cf4f5f8bedc56b3cc27dd2f7d88ed889b"
		os = "linux"
		filetype = "script"

	strings:
		$ = "/bin/bash -i >& /dev/tcp/" ascii

	condition:
		1 of them
}
