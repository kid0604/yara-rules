import "pe"

rule nAspyUpdateStrings : nAspyUpdate Family
{
	meta:
		description = "nAspyUpdate Identifying Strings"
		author = "Seth Hardy"
		last_modified = "2014-07-14"
		os = "windows"
		filetype = "executable"

	strings:
		$ = "\\httpclient.txt"
		$ = "password <=14"
		$ = "/%ldn.txt"
		$ = "Kill You\x00"

	condition:
		any of them
}
