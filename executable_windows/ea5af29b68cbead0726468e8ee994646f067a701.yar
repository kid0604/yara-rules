import "pe"

rule NaikonStrings : Naikon Family
{
	meta:
		description = "Naikon Identifying Strings"
		author = "Seth Hardy"
		last_modified = "2014-06-25"
		os = "windows"
		filetype = "executable"

	strings:
		$ = "NOKIAN95/WEB"
		$ = "/tag=info&id=15"
		$ = "skg(3)=&3.2d_u1"
		$ = "\\Temp\\iExplorer.exe"
		$ = "\\Temp\\\"TSG\""

	condition:
		any of them
}
