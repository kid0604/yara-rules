rule INDICATOR_TOOL_OwlProxy
{
	meta:
		author = "ditekSHen"
		description = "Hunt for OwlProxy"
		os = "windows"
		filetype = "executable"

	strings:
		$is1 = "call_new command: " wide
		$is2 = "call_proxy cmd: " wide
		$is3 = "download_file: " wide
		$is4 = "cmdhttp_run" wide
		$is5 = "sub_proxyhttp_run" wide
		$is6 = "proxyhttp_run" wide
		$is7 = "webshell_run" wide
		$is8 = "/exchangetopicservices/" fullword wide
		$is9 = "c:\\windows\\system32\\wmipd.dll" fullword wide
		$iu1 = "%s://+:%d%s" wide
		$iu2 = "%s://+:%d%spp/" wide
		$iu3 = "%s://+:%d%spx/" wide

	condition:
		uint16(0)==0x5a4d and 6 of ($is*) or ( all of ($iu*) and 2 of ($is*))
}
