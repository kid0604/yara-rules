import "pe"

rule NSFreeCode : NSFree Family
{
	meta:
		description = "NSFree code features"
		author = "Seth Hardy"
		last_modified = "2014-06-24"
		os = "windows"
		filetype = "executable"

	strings:
		$ = { 53 56 57 66 81 38 4D 5A }
		$ = { 90 90 90 90 81 3F 50 45 00 00 }

	condition:
		all of them
}
