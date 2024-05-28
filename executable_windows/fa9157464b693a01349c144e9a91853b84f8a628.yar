import "pe"

rule MALWARE_Win_ScoutElite
{
	meta:
		author = "ditekSHen"
		description = "Detects ScoutElite"
		reference = "https://github.com/ditekshen/back-in-2017"
		os = "windows"
		filetype = "executable"

	strings:
		$cmd1 = "command=scote_ping" fullword ascii
		$cmd2 = "command=scote_info_ipconfig" fullword ascii
		$cmd3 = "command=scote_info_systeminfo" fullword ascii
		$cmd4 = "command=scote_connection|hwid=" fullword ascii
		$cmd5 = "command=ping" fullword wide
		$cmd6 = "command=screen_capture_init" fullword wide
		$cmd7 = "command=screen_capture" fullword wide
		$cmd8 = "command=silence_screenshot" fullword wide
		$cmd9 = "command=silence_keylogger" fullword wide
		$cmd10 = "command=silence_password" fullword wide
		$cmd11 = "command=screen_thumb" fullword wide
		$cmd12 = "command=filemanager_upload_tcp" fullword wide
		$cmd13 = "command=filemanager_download" fullword wide
		$cmd14 = "command=filemanager_init" fullword wide
		$cmd15 = "command=filemanager_root" fullword wide
		$cmd16 = "command=filemanager_folder_filemanager_file" fullword wide
		$cmd17 = "command=filemanager_thumb" fullword wide
		$cmd18 = "command=keylogger_init" fullword wide
		$cmd19 = "command=keylogger_file" fullword wide
		$cmd20 = "command=password_firefox" fullword wide
		$cmd21 = "command=password_opera" fullword wide
		$cmd22 = "command=password_chrome" fullword wide
		$cmd23 = "command=password_all" fullword wide
		$cmd24 = "command=password_init" fullword wide
		$cmd25 = "command=misc_init" fullword wide
		$cmd26 = "command=misc_process" fullword wide
		$cmd27 = "command=misc_cmd" fullword wide
		$cmd28 = "command=new_rcs" fullword wide
		$cmd29 = "command=microphone_capture" fullword wide
		$cmd30 = "command=microphone_capture_init" fullword wide
		$cmd31 = "command=rvmedia_capture_init" fullword wide
		$cmd32 = "command=rvmedia_list" fullword wide
		$cmd33 = "command=rvmedia_resolution" fullword wide
		$cmd34 = "command=webcam_capture_init" fullword wide
		$cmd35 = "command=webcam_list" fullword wide
		$cmd36 = "command=webcam_resolution" fullword wide
		$cmd37 = "command=webcam_capture" fullword wide
		$gcmd1 = "filemanager_download_ftp" fullword wide
		$gcmd2 = "download_file_ftp" fullword wide
		$gcmd3 = "filemanager_upload_http" fullword wide
		$gcmd4 = "upload_file_http" fullword wide
		$gcmd5 = "upload_url" fullword wide
		$gcmd6 = "filemanager_delete" fullword wide
		$gcmd7 = "filemanager_execute_file" fullword wide
		$gcmd8 = /(microphone|webcam|rvmedia|keylogger|password|screen|filemanager)_(host|port|guid)/ nocase
		$confs1 = "[nick_name]" fullword ascii
		$confe1 = "[/nick_name]" fullword ascii wide
		$confs2 = "[install_name]" fullword ascii wide
		$confe2 = "[/install_name]" fullword ascii wide
		$confs3 = "[install_folder]" fullword ascii wide
		$confe3 = "[/install_folder]" fullword ascii wide
		$confs4 = "[reg_startup]" fullword ascii wide
		$confe4 = "[/reg_startup]" fullword ascii wide
		$confs5 = "[folder_startup]" fullword ascii wide
		$confe5 = "[/folder_startup]" fullword ascii wide
		$confs6 = "[task_startup]" fullword ascii wide
		$confe6 = "[/task_startup]" fullword ascii wide
		$confs7 = "[injection]" fullword ascii wide
		$confe7 = "[/injection]" fullword ascii wide
		$confs8 = "[injection_process]" fullword ascii wide
		$confe8 = "[/injection_process]" fullword ascii wide
		$confs9 = "[connection]" fullword ascii wide
		$confe9 = "[/connection]" fullword ascii wide

	condition:
		( uint16(0)==0x5a4d and (2 of ($cmd*) or 7 of ($gcmd*) or (2 of ($confs*) and 2 of ($confe*)) or (pe.exports("__elite") and 2 of them ))) or (15 of them )
}
