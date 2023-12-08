rule INDICATOR_TOOL_DogzProxy
{
	meta:
		author = "ditekSHen"
		description = "Detects Dogz proxy tool"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "LOGONSERVER=" fullword wide
		$s2 = "DOGZ_E_" ascii
		$s3 = "got handshake_id=%d" ascii
		$s4 = "responser send connect ack" ascii
		$s5 = "dogz " ascii

	condition:
		uint16(0)==0x5a4d and 4 of them
}
