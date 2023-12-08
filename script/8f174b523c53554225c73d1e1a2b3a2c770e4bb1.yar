import "pe"

rule IMulerStrings : IMuler Family
{
	meta:
		description = "IMuler Identifying Strings"
		author = "Seth Hardy"
		last_modified = "2014-06-16"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$ = "/cgi-mac/"
		$ = "xnocz1"
		$ = "checkvir.plist"
		$ = "/Users/apple/Documents/mac back"
		$ = "iMuler2"
		$ = "/Users/imac/Desktop/macback/"
		$ = "xntaskz.gz"
		$ = "2wmsetstatus.cgi"
		$ = "launch-0rp.dat"
		$ = "2wmupload.cgi"
		$ = "xntmpz"
		$ = "2wmrecvdata.cgi"
		$ = "xnorz6"
		$ = "2wmdelfile.cgi"
		$ = "/LanchAgents/checkvir"
		$ = "0PERA:%s"
		$ = "/tmp/Spotlight"
		$ = "/tmp/launch-ICS000"

	condition:
		any of them
}
