rule jsp_cmd : webshell
{
	meta:
		description = "Laudanum Injector Tools - file cmd.war"
		author = "Florian Roth"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "55e4c3dc00cfab7ac16e7cfb53c11b0c01c16d3d"
		os = "windows,linux,macos"
		filetype = "script"

	strings:
		$s0 = "cmd.jsp}" fullword ascii
		$s1 = "cmd.jspPK" fullword ascii
		$s2 = "WEB-INF/web.xml" fullword ascii
		$s3 = "WEB-INF/web.xmlPK" fullword ascii
		$s4 = "META-INF/MANIFEST.MF" fullword ascii

	condition:
		uint16(0)==0x4b50 and filesize <2KB and all of them
}
