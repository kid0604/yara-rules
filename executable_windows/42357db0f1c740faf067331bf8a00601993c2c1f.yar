import "pe"

rule EquationGroup_DXGHLP16
{
	meta:
		description = "EquationGroup Malware - file DXGHLP16.SYS"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/tcSoiJ"
		date = "2017-01-13"
		modified = "2023-01-06"
		hash1 = "fcfb56fa79d2383d34c471ef439314edc2239d632a880aa2de3cea430f6b5665"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "DXGHLP16.SYS" fullword wide
		$s2 = "P16.SYS" fullword ascii
		$s3 = "\\Registry\\User\\CurrentUser\\" wide
		$s4 = "\\DosDevices\\%ws" wide
		$s5 = "\\Device\\%ws_%ws" wide
		$s6 = "ct@SYS\\DXGHLP16.dbg" fullword ascii
		$s7 = "%ws%03d%ws%wZ" fullword wide
		$s8 = "TCP/IP driver" fullword wide
		$s9 = "\\Device\\%ws" wide

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and all of them )
}
