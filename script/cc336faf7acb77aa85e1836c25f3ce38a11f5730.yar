rule indoexploit_autoexploiter
{
	meta:
		description = "Detects the presence of IndoXploit Auto Xploiter"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$ = "echo \"IndoXploit - Auto Xploiter\""

	condition:
		any of them
}
