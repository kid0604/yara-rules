import "pe"

rule DarkComet_Keylogger_File : RAT
{
	meta:
		author = "Florian Roth"
		description = "Looks like a keylogger file created by DarkComet Malware"
		date = "25.07.14"
		reference = "https://raw.githubusercontent.com/Neo23x0/Loki/master/signatures/thor-hacktools.yar"
		score = 50
		os = "windows"
		filetype = "executable"

	strings:
		$magic = "::"
		$entry = /\n:: [A-Z]/
		$timestamp = /\([0-9]?[0-9]:[0-9][0-9]:[0-9][0-9] [AP]M\)/

	condition:
		($magic at 0) and #entry>10 and #timestamp>10
}
