import "pe"

rule WimmieStrings : Wimmie Family
{
	meta:
		description = "Strings used by Wimmie"
		author = "Seth Hardy"
		last_modified = "2014-07-17"
		os = "windows"
		filetype = "executable"

	strings:
		$ = "\x00ScriptMan"
		$ = "C:\\WINDOWS\\system32\\sysprep\\cryptbase.dll" wide ascii
		$ = "ProbeScriptFint" wide ascii
		$ = "ProbeScriptKids"

	condition:
		any of them
}
