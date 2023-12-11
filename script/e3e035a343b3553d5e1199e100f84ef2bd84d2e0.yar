import "pe"

rule HKTL_shellpop_TCLsh
{
	meta:
		description = "Detects suspicious TCLsh popshell"
		author = "Tobias Michalski"
		reference = "https://github.com/0x00-0x00/ShellPop"
		date = "2018-05-18"
		hash1 = "9f49d76d70d14bbe639a3c16763d3b4bee92c622ecb1c351cb4ea4371561e133"
		os = "windows,linux,macos"
		filetype = "script"

	strings:
		$s1 = "{ puts -nonewline $s \"shell>\";flush $s;gets $s c;set e \"exec $c\";if" ascii

	condition:
		filesize <1KB and 1 of them
}
