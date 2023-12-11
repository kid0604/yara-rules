import "pe"

rule EnfalStrings : Enfal Family
{
	meta:
		description = "Enfal Identifying Strings"
		author = "Seth Hardy"
		last_modified = "2014-06-19"
		os = "windows"
		filetype = "executable"

	strings:
		$ = "D:\\work\\\xe6\xba\x90\xe5\x93\xa5\xe5\x85\x8d\xe6\x9d\x80\\tmp\\Release\\ServiceDll.pdb"
		$ = "e:\\programs\\LuridDownLoader"
		$ = "LuridDownloader for Falcon"
		$ = "DllServiceTrojan"
		$ = "\\k\\\xe6\xa1\x8c\xe8\x9d\xa2\\"
		$ = "EtenFalcon\xef\xbc\x88\xe4\xbf\xae\xe6\x94\xb9\xef\xbc\x89"
		$ = "Madonna\x00Jesus"
		$ = "/iupw82/netstate"
		$ = "fuckNodAgain"
		$ = "iloudermao"
		$ = "Crpq2.cgi"
		$ = "Clnpp5.cgi"
		$ = "Dqpq3ll.cgi"
		$ = "dieosn83.cgi"
		$ = "Rwpq1.cgi"
		$ = "/Ccmwhite"
		$ = "/Cmwhite"
		$ = "/Crpwhite"
		$ = "/Dfwhite"
		$ = "/Query.txt"
		$ = "/Ufwhite"
		$ = "/cgl-bin/Clnpp5.cgi"
		$ = "/cgl-bin/Crpq2.cgi"
		$ = "/cgl-bin/Dwpq3ll.cgi"
		$ = "/cgl-bin/Owpq4.cgi"
		$ = "/cgl-bin/Rwpq1.cgi"
		$ = "/trandocs/mm/"
		$ = "/trandocs/netstat"
		$ = "NFal.exe"
		$ = "LINLINVMAN"
		$ = "7NFP4R9W"

	condition:
		any of them
}
