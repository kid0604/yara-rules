import "pe"
import "time"

rule INDICATOR_SUSPICIOUS_AHK_Downloader
{
	meta:
		description = "Detects AutoHotKey binaries acting as second stage droppers"
		author = "ditekSHen"
		os = "windows"
		filetype = "executable"

	strings:
		$d1 = "URLDownloadToFile, http" ascii
		$d2 = "URLDownloadToFile, file" ascii
		$s1 = ">AUTOHOTKEY SCRIPT<" fullword wide
		$s2 = "open \"%s\" alias AHK_PlayMe" fullword wide
		$s3 = /AHK\s(Keybd|Mouse)/ fullword wide

	condition:
		uint16(0)==0x5a4d and (1 of ($d*) and 1 of ($s*))
}
