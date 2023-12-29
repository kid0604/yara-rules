import "pe"

rule MALWARE_Win_VBSDownloader
{
	meta:
		author = "ditekShen"
		description = "Detects second stage VBS downloader of third stage VBS"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "CreateObject(\"MSXML2.ServerXMLHTTP\")" wide
		$s2 = ".Open \"GET\"," wide
		$s3 = ".Send" wide
		$s4 = ".responseText" wide
		$s5 = "ExecuteGlobal" wide

	condition:
		filesize <50KB and all of them
}
