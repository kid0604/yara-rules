import "pe"
import "math"

rule HasModified_DOS_Message : PECheck
{
	meta:
		author = "_pusher_"
		description = "DOS Message Check"
		date = "2016-07"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = "This program must be run under Win32" wide ascii nocase
		$a1 = "This program cannot be run in DOS mode" wide ascii nocase
		$a2 = "This program requires Win32" wide ascii nocase
		$a3 = "This program must be run under Win64" wide ascii nocase

	condition:
		uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550 and not ( for any of ($a*) : ($ in (0x0.. uint32(0x3c))))
}
