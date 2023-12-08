import "time"
import "pe"

rule INDICATOR_SUSPICIOUS_EXE_B64_Encoded_UserAgent
{
	meta:
		author = "ditekSHen"
		description = "Detects executables containing base64 encoded User Agent"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "TW96aWxsYS81LjAgK" ascii wide
		$s2 = "TW96aWxsYS81LjAgKFdpbmRvd3M" ascii wide

	condition:
		uint16(0)==0x5a4d and any of them
}
