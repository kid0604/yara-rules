rule KiwiTaskmgr_2
{
	meta:
		description = "Chinese Hacktool Set - file KiwiTaskmgr.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "8bd6c9f2e8be3e74bd83c6a2d929f8a69422fb16"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Process Ok, Memory Ok, resuming process :)" fullword wide
		$s2 = "Kiwi Taskmgr no-gpo" fullword wide
		$s3 = "KiwiAndTaskMgr" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <300KB and all of them
}
