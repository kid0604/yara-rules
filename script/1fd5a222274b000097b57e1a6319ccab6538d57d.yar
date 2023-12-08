rule Z_WebShell
{
	meta:
		author = "NCSC"
		description = "Detects Z Webshell from NCSC report"
		reference = "https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control"
		date = "2018/04/06"
		hash = "ace12552f3a980f1eed4cadb02afe1bfb851cafc8e58fb130e1329719a07dbf0"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$ = "Z_PostBackJS" ascii wide
		$ = "z_file_download" ascii wide
		$ = "z_WebShell" ascii wide
		$ = "1367948c7859d6533226042549228228" ascii wide

	condition:
		3 of them
}
