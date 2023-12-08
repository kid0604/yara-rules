import "pe"

rule DarkComet_Keylogger_File_alt_1
{
	meta:
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		description = "Looks like a keylogger file created by DarkComet Malware"
		date = "25.07.14"
		score = 50
		os = "windows"
		filetype = "executable"

	strings:
		$entry = /\n:: [A-Z]/
		$timestamp = /\([0-9]?[0-9]:[0-9][0-9]:[0-9][0-9] [AP]M\)/

	condition:
		uint16(0)==0x3A3A and #entry>10 and #timestamp>10
}
