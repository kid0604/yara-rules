import "math"

rule WEBSHELL_JSP_Input_Upload_Write_alt_2
{
	meta:
		description = "JSP uploader which gets input, writes files and contains \"upload\""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		score = 75
		date = "2021/01/24"
		modified = "2024-12-09"
		hash = "ef98ca135dfb9dcdd2f730b18e883adf50c4ab82"
		hash = "583231786bc1d0ecca7d8d2b083804736a3f0a32"
		hash = "19eca79163259d80375ebebbc440b9545163e6a3"
		id = "bbf26edd-88b7-5ec5-a16e-d96a086dcd19"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$upload = "upload" nocase wide ascii
		$write1 = "os.write" fullword wide ascii
		$write2 = "FileOutputStream" fullword wide ascii
		$cjsp_short1 = "<%" ascii wide
		$cjsp_short2 = "%>" wide ascii
		$cjsp_long1 = "<jsp:" ascii wide
		$cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
		$cjsp_long3 = "/jstl/core" ascii wide
		$cjsp_long4 = "<%@p" nocase ascii wide
		$cjsp_long5 = "<%@ " nocase ascii wide
		$cjsp_long6 = "<% " ascii wide
		$cjsp_long7 = "< %" ascii wide
		$input1 = "getParameter" fullword ascii wide
		$input2 = "getHeaders" fullword ascii wide
		$input3 = "getInputStream" fullword ascii wide
		$input4 = "getReader" fullword ascii wide
		$req1 = "request" fullword ascii wide
		$req2 = "HttpServletRequest" fullword ascii wide
		$req3 = "getRequest" fullword ascii wide

	condition:
		filesize <10KB and ($cjsp_short1 at 0 or any of ($cjsp_long*) or ($cjsp_short1 and $cjsp_short2 in ( filesize -100.. filesize )) or ($cjsp_short2 and ($cjsp_short1 in (0..1000) or $cjsp_short1 in ( filesize -1000.. filesize )))) and ( any of ($input*) and any of ($req*)) and $upload and 1 of ($write*)
}
