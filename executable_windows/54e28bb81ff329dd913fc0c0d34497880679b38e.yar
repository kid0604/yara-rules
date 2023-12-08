import "pe"

rule YayihStrings : Yayih Family
{
	meta:
		description = "Yayih Identifying Strings"
		author = "Seth Hardy"
		last_modified = "2014-07-11"
		os = "windows"
		filetype = "executable"

	strings:
		$ = "/bbs/info.asp"
		$ = "\\msinfo.exe"
		$ = "%s\\%srcs.pdf"
		$ = "\\aumLib.ini"

	condition:
		any of them
}
