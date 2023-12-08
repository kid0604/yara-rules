import "pe"

rule fgexec
{
	meta:
		description = "Detects a tool used by APT groups - file fgexec.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/igxLyF"
		date = "2016-09-08"
		hash1 = "8697897bee415f213ce7bc24f22c14002d660b8aaffab807490ddbf4f3f20249"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "\\Release\\fgexec.pdb" ascii
		$x2 = "fgexec Remote Process Execution Tool" fullword ascii
		$x3 = "fgexec CallNamedPipe failed" fullword ascii
		$x4 = "fizzgig and the mighty foofus.net team" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <100KB and 1 of ($x*)) or (3 of them )
}
