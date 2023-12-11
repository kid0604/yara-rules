rule ReconCommands_in_File : FILE
{
	meta:
		description = "Detects various recon commands in a single file"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/haroonmeer/status/939099379834658817"
		date = "2017-12-11"
		score = 40
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$ = "tasklist"
		$ = "net time"
		$ = "systeminfo"
		$ = "whoami"
		$ = "nbtstat"
		$ = "net start"
		$ = "qprocess"
		$ = "nslookup"

	condition:
		filesize <5KB and 4 of them
}
