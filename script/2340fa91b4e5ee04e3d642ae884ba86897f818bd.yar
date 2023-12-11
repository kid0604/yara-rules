rule CN_Honker_Webshell_test3693
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file test3693.war"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "246d629ae3ad980b5bfe7e941fe90b855155dbfc"
		os = "windows"
		filetype = "script"

	strings:
		$s0 = "Process p=Runtime.getRuntime().exec(\"cmd /c \"+strCmd);" fullword ascii
		$s2 = "http://www.topronet.com </font>\",\" <font color=red> Thanks for your support - " ascii

	condition:
		uint16(0)==0x4b50 and filesize <50KB and all of them
}
