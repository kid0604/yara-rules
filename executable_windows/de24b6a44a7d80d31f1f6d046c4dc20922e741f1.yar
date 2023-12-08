import "pe"

rule iexpl0reStrings : iexpl0re Family
{
	meta:
		description = "Strings used by iexpl0re"
		author = "Seth Hardy"
		last_modified = "2014-07-21"
		os = "windows"
		filetype = "executable"

	strings:
		$ = "%USERPROFILE%\\IEXPL0RE.EXE"
		$ = "\"<770j (("
		$ = "\\Users\\%s\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\IEXPL0RE.LNK"
		$ = "\\Documents and Settings\\%s\\Application Data\\Microsoft\\Internet Explorer\\IEXPL0RE.EXE"
		$ = "LoaderV5.dll"
		$ = "POST /index%0.9d.asp HTTP/1.1"
		$ = "GET /search?n=%0.9d&"
		$ = "DUDE_AM_I_SHARP-3.14159265358979x6.626176"
		$ = "WHO_A_R_E_YOU?2.99792458x1.25663706143592"
		$ = "BASTARD_&&_BITCHES_%0.8x"
		$ = "c:\\bbb\\eee.txt"

	condition:
		any of them
}
