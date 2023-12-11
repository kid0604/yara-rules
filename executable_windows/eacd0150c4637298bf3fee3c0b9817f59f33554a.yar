import "pe"

rule MongalStrings
{
	meta:
		description = "Mongal Identifying Strings"
		author = "Seth Hardy"
		last_modified = "2014-07-15"
		os = "windows"
		filetype = "executable"

	strings:
		$ = "NSCortr.dll"
		$ = "NSCortr1.dll"
		$ = "Sina.exe"

	condition:
		any of them
}
