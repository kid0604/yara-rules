rule RDP_Brute_Strings
{
	meta:
		author = "NCSC"
		description = "Detects RDP brute forcer from NCSC report"
		reference = "https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control"
		date = "2018/04/06"
		hash = "8234bf8a1b53efd2a452780a69666d1aedcec9eb1bb714769283ccc2c2bdcc65"
		os = "windows"
		filetype = "script"

	strings:
		$ = "RDP Brute" ascii wide
		$ = "RdpChecker" ascii
		$ = "RdpBrute" ascii
		$ = "Brute_Count_Password" ascii
		$ = "BruteIPList" ascii
		$ = "Chilkat_Socket_Key" ascii
		$ = "Brute_Sync_Stat" ascii
		$ = "(Error! Hyperlink reference not valid.)" wide
		$ = "BadRDP" wide
		$ = "GoodRDP" wide
		$ = "@echo off{0}:loop{0}del {1}{0}if exist {1} goto loop{0}del {2}{0}del \"{2}\"" wide
		$ = "Coded by z668" wide

	condition:
		4 of them
}
