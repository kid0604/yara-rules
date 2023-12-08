import "pe"

rule RemCom_RemoteCommandExecution
{
	meta:
		description = "Detects strings from RemCom tool"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/tezXZt"
		date = "2017-12-28"
		score = 50
		os = "windows"
		filetype = "executable"

	strings:
		$ = "\\\\.\\pipe\\%s%s%d"
		$ = "%s\\pipe\\%s%s%d%s"
		$ = "\\ADMIN$\\System32\\%s%s"

	condition:
		1 of them
}
