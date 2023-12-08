rule SQLMap
{
	meta:
		author = "Florian Roth"
		description = "This signature detects the SQLMap SQL injection tool"
		date = "07/2014"
		score = 60
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "except SqlmapBaseException, ex:"

	condition:
		1 of them
}
