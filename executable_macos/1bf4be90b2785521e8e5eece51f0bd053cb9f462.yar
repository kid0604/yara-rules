import "pe"

rule MacControlStrings : MacControl Family
{
	meta:
		description = "MacControl Identifying Strings"
		author = "Seth Hardy"
		last_modified = "2014-06-17"
		os = "macos"
		filetype = "executable"

	strings:
		$ = "HTTPHeadGet"
		$ = "/Library/launched"
		$ = "My connect error with no ip!"
		$ = "Send File is Failed"
		$ = "****************************You Have got it!****************************"

	condition:
		any of them
}
