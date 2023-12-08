import "pe"

rule FavoriteStrings : Favorite Family
{
	meta:
		description = "Favorite Identifying Strings"
		author = "Seth Hardy"
		last_modified = "2014-06-24"
		os = "windows"
		filetype = "executable"

	strings:
		$string1 = "!QAZ4rfv"
		$file1 = "msupdater.exe"
		$file2 = "FAVORITES.DAT"

	condition:
		any of ($string*) or all of ($file*)
}
