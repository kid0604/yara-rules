rule BlackTech_Flagprodownloader_str
{
	meta:
		description = "Flagpro downloader in BlackTech"
		author = "JPCERT/CC Incident Response Group"
		hash = "e197c583f57e6c560b576278233e3ab050e38aa9424a5d95b172de66f9cfe970"
		os = "windows"
		filetype = "executable"

	strings:
		$msg1 = "download...." ascii wide
		$msg2 = "download1 finished!" ascii wide
		$msg3 = "download2 finished!" ascii wide
		$msg4 = "start get all pass!" ascii wide
		$msg5 = "start get all pass 1!" ascii wide
		$msg6 = "init Refresh...'" ascii wide
		$msg7 = "busy stop..." ascii wide
		$msg8 = "success!" ascii wide
		$msg9 = "failed!" ascii wide
		$msg10 = "~MYTEMP" ascii wide
		$msg11 = "ExecYes" ascii wide
		$msg12 = "flagpro=" ascii wide

	condition:
		uint16(0)==0x5A4D and uint32( uint32(0x3c))==0x00004550 and 6 of them
}
