rule scriptkiddies
{
	meta:
		description = "Detects strings associated with known script kiddie groups"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$ = "lastc0de@Outlook.com" nocase
		$ = "CodersLeet" nocase
		$ = "AgencyCaFc" nocase
		$ = "IndoXploit" nocase
		$ = "Kapaljetz666" nocase

	condition:
		any of them and filesize <500KB
}
