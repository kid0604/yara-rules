import "pe"
import "math"

rule QtFrameWork
{
	meta:
		author = "_pusher_"
		date = "2016-08"
		description = "Detects the presence of Qt framework libraries"
		os = "windows"
		filetype = "executable"

	strings:
		$aa0 = "\x00Qt5Core.dll\x00" ascii
		$aa1 = "\x00QtCore4.dll\x00" ascii

	condition:
		( any of ($aa*))
}
