rule APT30_Sample_5
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "1a2dd2a0555dc746333e7c956c58f7c4cdbabd4b"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "Version 4.7.3001" fullword wide
		$s1 = "Copyright (c) Microsoft Corporation 2004" fullword wide
		$s3 = "Microsoft(R) is a registered trademark of Microsoft Corporation in the U" wide
		$s7 = "msmsgs" fullword wide
		$s10 = "----------------g_nAV=%d,hWnd:0x%X,className:%s,Title:%s,(%d,%d,%d,%d),BOOL=%d" fullword ascii

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
