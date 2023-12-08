import "pe"

rule ScarhiknStrings : Scarhikn Family
{
	meta:
		description = "Scarhikn Identifying Strings"
		author = "Seth Hardy"
		last_modified = "2014-06-25"
		os = "windows"
		filetype = "executable"

	strings:
		$ = "9887___skej3sd"
		$ = "haha123"

	condition:
		any of them
}
