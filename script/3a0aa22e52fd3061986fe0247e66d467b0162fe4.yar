import "pe"

rule SUSP_shellpop_Bash_alt_2
{
	meta:
		description = "Detects susupicious bash command"
		author = "Tobias Michalski"
		reference = "https://github.com/0x00-0x00/ShellPop"
		date = "2018-05-18"
		modified = "2021-01-25"
		score = 70
		hash1 = "36fad575a8bc459d0c2e3ad626e97d5cf4f5f8bedc56b3cc27dd2f7d88ed889b"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$x1 = "bash -i >& /dev/tcp/" ascii
		$fp1 = "bash -i >& /dev/tcp/IP/PORT" ascii

	condition:
		$x1 and not 1 of ($fp*)
}
