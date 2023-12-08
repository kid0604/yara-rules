import "pe"

rule OlyxStrings : Olyx Family
{
	meta:
		description = "Olyx Identifying Strings"
		author = "Seth Hardy"
		last_modified = "2014-06-19"
		os = "macos"
		filetype = "executable"

	strings:
		$ = "/Applications/Automator.app/Contents/MacOS/DockLight"

	condition:
		any of them
}
