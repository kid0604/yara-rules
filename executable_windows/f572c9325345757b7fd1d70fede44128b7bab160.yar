import "pe"

rule NetTravStrings : NetTraveler Family
{
	meta:
		description = "Identifiers for NetTraveler DLL"
		author = "Katie Kleemola"
		last_updated = "2014-05-20"
		os = "windows"
		filetype = "executable"

	strings:
		$ = "?action=updated&hostid="
		$ = "travlerbackinfo"
		$ = "?action=getcmd&hostid="
		$ = "%s?action=gotcmd&hostid="
		$ = "%s?hostid=%s&hostname=%s&hostip=%s&filename=%s&filestart=%u&filetext="
		$ = "\x00Method1 Fail!!!!!\x00"
		$ = "\x00Method3 Fail!!!!!\x00"
		$ = "\x00method currect:\x00"
		$ = /\x00\x00[\w\-]+ is Running!\x00\x00/
		$ = "\x00OtherTwo\x00"

	condition:
		any of them
}
