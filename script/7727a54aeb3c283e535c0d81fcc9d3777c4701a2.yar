import "pe"

rule sig_24952_files_ccc_fileserv_nocmd
{
	meta:
		description = "24952-files - file nocmd.vbs"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com/2024/06/10/icedid-brings-screenconnect-and-csharp-streamer-to-alphv-ransomware-deployment"
		date = "2024-05-27"
		hash1 = "457a2f29d395c04a6ad6012fab4d30e04d99d7fc8640a9ee92e314185cc741d3"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "WshShell.Run chr(34) & \"c:\\programdata\\rcl.bat\" & Chr(34), 0" fullword ascii
		$s2 = "Set WshShell = Nothing" fullword ascii
		$s3 = "Set WshShell = CreateObject(\"WScript.Shell\")" fullword ascii

	condition:
		uint16(0)==0x6553 and filesize <1KB and all of them
}
