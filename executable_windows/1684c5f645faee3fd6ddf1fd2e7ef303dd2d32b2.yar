rule CN_Honker_struts2_catbox
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file catbox.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "ee8fbd91477e056aef34fce3ade474cafa1a4304"
		os = "windows"
		filetype = "executable"

	strings:
		$s6 = "'Toolmao box by gainover www.toolmao.com" fullword ascii
		$s20 = "{external.exeScript(_toolmao_bgscript[i],'javascript',false);}}" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <8160KB and all of them
}
