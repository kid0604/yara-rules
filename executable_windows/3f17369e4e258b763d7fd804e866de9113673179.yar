import "pe"

rule DarkComet_4 : RAT
{
	meta:
		reference = "https://github.com/bwall/bamfdetect/blob/master/BAMF_Detect/modules/yara/darkcomet.yara"
		description = "Detects DarkComet RAT based on specific strings"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "#BOT#"
		$a2 = "WEBCAMSTOP"
		$a3 = "UnActiveOnlineKeyStrokes"
		$a4 = "#SendTaskMgr"
		$a5 = "#RemoteScreenSize"
		$a6 = "ping 127.0.0.1 -n 4 > NUL &&"

	condition:
		all of them
}
