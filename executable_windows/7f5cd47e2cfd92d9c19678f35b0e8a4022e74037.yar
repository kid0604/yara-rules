import "pe"

rule QuarianStrings : Quarian Family
{
	meta:
		description = "Quarian Identifying Strings"
		author = "Seth Hardy"
		last_modified = "2014-07-09"
		os = "windows"
		filetype = "executable"

	strings:
		$ = "s061779s061750"
		$ = "[OnUpLoadFile]"
		$ = "[OnDownLoadFile]"
		$ = "[FileTransfer]"
		$ = "---- Not connect the Manager, so start UnInstall ----"
		$ = "------- Enter CompressDownLoadDir ---------"
		$ = "------- Enter DownLoadDirectory ---------"
		$ = "[HandleAdditionalData]"
		$ = "[mswsocket.dll]"
		$ = "msupdate.dll........Enter ThreadCmd!"
		$ = "ok1-1"
		$ = "msupdate_tmp.dll"
		$ = "replace Rpcss.dll successfully!"
		$ = "f:\\loadhiddendriver-mdl\\objfre_win7_x86\\i386\\intelnat.pdb"
		$ = "\\drivercashe\\" wide ascii
		$ = "\\microsoft\\windwos\\" wide ascii
		$ = "\\DosDevices\\LOADHIDDENDRIVER" wide ascii
		$ = "\\Device\\LOADHIDDENDRIVER" wide ascii
		$ = "Global\\state_maping" wide ascii
		$ = "E:\\Code\\2.0\\2.0_multi-port\\2.0\\ServerInstall_New-2010-0913_sp3\\msupdataDll\\Release\\msupdate_tmp.pdb"
		$ = "Global\\unInstall_event_1554_Ower" wide ascii

	condition:
		any of them
}
