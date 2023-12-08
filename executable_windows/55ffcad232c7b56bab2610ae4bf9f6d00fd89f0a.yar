rule HYTop_CaseSwitch_2005
{
	meta:
		description = "Webshells Auto-generated - file 2005.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "8bf667ee9e21366bc0bd3491cb614f41"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "MSComDlg.CommonDialog"
		$s2 = "CommonDialog1"
		$s3 = "__vbaExceptHandler"
		$s4 = "EVENT_SINK_Release"
		$s5 = "EVENT_SINK_AddRef"
		$s6 = "By Marcos"
		$s7 = "EVENT_SINK_QueryInterface"
		$s8 = "MethCallEngine"

	condition:
		all of them
}
