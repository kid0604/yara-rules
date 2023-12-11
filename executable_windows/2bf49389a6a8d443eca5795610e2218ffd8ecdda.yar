import "pe"

rule NSFreeStrings : NSFree Family
{
	meta:
		description = "NSFree Identifying Strings"
		author = "Seth Hardy"
		last_modified = "2014-06-24"
		os = "windows"
		filetype = "executable"

	strings:
		$ = "\\MicNS\\" nocase
		$ = "NSFreeDll" wide ascii
		$ = { 0c 30 31 2b 78 28 2a 37 3f 2a 39 35 78 3b 39 36 36 37 }

	condition:
		any of them
}
