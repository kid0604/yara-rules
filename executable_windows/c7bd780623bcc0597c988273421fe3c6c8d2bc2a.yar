rule generic_shellcode_downloader_specific
{
	meta:
		author = "NCSC"
		description = "Detects Doorshell from NCSC report"
		reference = "https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control"
		date = "2018/04/06"
		hash = "b8bc0611a7fd321d2483a0a9a505251e15c22402e0cfdc62c0258af53ed3658a"
		os = "windows"
		filetype = "executable"

	strings:
		$push1 = {68 6C 6C 6F 63}
		$push2 = {68 75 61 6C 41}
		$push3 = {68 56 69 72 74}
		$a = {BA 90 02 00 00 46 C1 C6 19 03 DD 2B F4 33 DE}
		$b = {87 C0 81 F2 D1 19 89 14 C1 C8 1F FF E0}

	condition:
		( uint16(0)==0x5A4D and uint16( uint32(0x3C))==0x4550) and ($a or $b) and @push1<@push2 and @push2<@push3
}
