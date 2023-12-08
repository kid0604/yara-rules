rule googieplay_js
{
	meta:
		description = "Detects suspicious JavaScript code related to Google Play"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$ = "tdsjqu!tsd>#iuuq;00hpphjfqmbz/jogp0nbhfoup`hpphjfqmbz/kt#?=0tdsjqu?"

	condition:
		any of them
}
