rule HScan_v1_20_oncrpc
{
	meta:
		description = "Chinese Hacktool Set - file oncrpc.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "e8f047eed8d4f6d2f5dbaffdd0e6e4a09c5298a2"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "clnt_raw.c - Fatal header serialization error." fullword ascii
		$s2 = "svctcp_.c - cannot getsockname or listen" fullword ascii
		$s3 = "too many connections (%d), compilation constant FD_SETSIZE was only %d" fullword ascii
		$s4 = "svc_run: - select failed" fullword ascii
		$s5 = "@(#)bindresvport.c" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <340KB and 4 of them
}
