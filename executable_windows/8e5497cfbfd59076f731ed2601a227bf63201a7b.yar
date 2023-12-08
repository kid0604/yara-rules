import "pe"

rule Win32FertgerHavex
{
	meta:
		Author = "BAE Systems"
		Date = "2014/06/23"
		Description = "Rule for identifying Fertger version of HAVEX"
		Reference = "www.f-secure.com/weblog/archives/00002718.html"
		description = "Identifies Fertger version of HAVEX"
		os = "windows"
		filetype = "executable"

	strings:
		$mz = "MZ"
		$a1 = "\\\\.\\pipe\\mypipe-f" wide
		$a2 = "\\\\.\\pipe\\mypipe-h" wide
		$a3 = "\\qln.dbx" wide
		$a4 = "*.yls" wide
		$a5 = "\\*.xmd" wide
		$a6 = "fertger" wide
		$a7 = "havex"

	condition:
		$mz at 0 and 3 of ($a*)
}
