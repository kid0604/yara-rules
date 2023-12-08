rule Ping_Command_in_EXE
{
	meta:
		description = "Detects an suspicious ping command execution in an executable"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2016-11-03"
		score = 60
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "cmd /c ping 127.0.0.1 -n " ascii

	condition:
		uint16(0)==0x5a4d and all of them
}
