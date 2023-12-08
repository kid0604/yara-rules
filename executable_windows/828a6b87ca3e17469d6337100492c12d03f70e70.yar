rule FreeVersion_debug
{
	meta:
		description = "Chinese Hacktool Set - file debug.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "d11e6c6f675b3be86e37e50184dadf0081506a89"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "c:\\Documents and Settings\\Administrator\\" fullword ascii
		$s1 = "Got WMI process Pid: %d" ascii
		$s2 = "This exploit will execute" ascii
		$s6 = "Found token %s " ascii
		$s7 = "Running reverse shell" ascii
		$s10 = "wmiprvse.exe" fullword ascii
		$s12 = "SELECT * FROM IIsWebInfo" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <820KB and 3 of them
}
