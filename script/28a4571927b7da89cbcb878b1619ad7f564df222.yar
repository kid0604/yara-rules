import "math"

rule WEBSHELL_ASP_Writer
{
	meta:
		description = "ASP webshell which only writes an uploaded file to disk"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		date = "2021/03/07"
		modified = "2023-07-05"
		score = 60
		hash = "df6eaba8d643c49c6f38016531c88332e80af33c"
		hash = "83642a926291a499916e8c915dacadd0d5a8b91f"
		hash = "5417fad68a6f7320d227f558bf64657fe3aa9153"
		hash = "97d9f6c411f54b56056a145654cd00abca2ff871"
		hash = "fc44fd7475ee6c0758ace2b17dd41ed7ea75cc73"
		os = "windows"
		filetype = "script"

	strings:
		$sus1 = "password" fullword wide ascii
		$sus2 = "pwd" fullword wide ascii
		$sus3 = "<asp:TextBox" fullword nocase wide ascii
		$sus4 = "\"upload\"" wide ascii
		$sus5 = "\"Upload\"" wide ascii
		$sus6 = "gif89" wide ascii
		$sus7 = "\"&\"" wide ascii
		$sus8 = "authkey" fullword wide ascii
		$sus9 = "AUTHKEY" fullword wide ascii
		$sus10 = "test.asp" fullword wide ascii
		$sus11 = "cmd.asp" fullword wide ascii
		$sus12 = ".Write(Request." wide ascii
		$sus13 = "<textarea " wide ascii
		$sus14 = "\"unsafe" fullword wide ascii
		$sus15 = "'unsafe" fullword wide ascii
		$sus16 = "Army" fullword wide ascii
		$tagasp_short1 = /<%[^"]/ wide ascii
		$tagasp_short2 = "%>" wide ascii
		$tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
		$tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
		$tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
		$tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
		$tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
		$tagasp_long10 = "<%@ " wide ascii
		$tagasp_long11 = /<% \w/ nocase wide ascii
		$tagasp_long12 = "<%ex" nocase wide ascii
		$tagasp_long13 = "<%ev" nocase wide ascii
		$tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii
		$tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
		$tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii
		$php1 = "<?php"
		$php2 = "<?="
		$jsp1 = "=\"java." wide ascii
		$jsp2 = "=\"javax." wide ascii
		$jsp3 = "java.lang." wide ascii
		$jsp4 = "public" fullword wide ascii
		$jsp5 = "throws" fullword wide ascii
		$jsp6 = "getValue" fullword wide ascii
		$jsp7 = "getBytes" fullword wide ascii
		$perl1 = "PerlScript" fullword
		$asp_input1 = "request" fullword nocase wide ascii
		$asp_input2 = "Page_Load" fullword nocase wide ascii
		$asp_input3 = "UmVxdWVzdC5Gb3JtK" fullword wide ascii
		$asp_xml_http = "Microsoft.XMLHTTP" fullword nocase wide ascii
		$asp_xml_method1 = "GET" fullword wide ascii
		$asp_xml_method2 = "POST" fullword wide ascii
		$asp_xml_method3 = "HEAD" fullword wide ascii
		$asp_form1 = "<form " wide ascii
		$asp_form2 = "<Form " wide ascii
		$asp_form3 = "<FORM " wide ascii
		$asp_asp = "<asp:" wide ascii
		$asp_text1 = ".text" wide ascii
		$asp_text2 = ".Text" wide ascii
		$asp_always_write1 = /\.write/ nocase wide ascii
		$asp_always_write2 = /\.swrite/ nocase wide ascii
		$asp_write_way_one2 = "SaveToFile" fullword nocase wide ascii
		$asp_write_way_one3 = "CREAtEtExtFiLE" fullword nocase wide ascii
		$asp_cr_write1 = "CreateObject(" nocase wide ascii
		$asp_cr_write2 = "CreateObject (" nocase wide ascii
		$asp_streamwriter1 = "streamwriter" fullword nocase wide ascii
		$asp_streamwriter2 = "filestream" fullword nocase wide ascii

	condition:
		(( any of ($tagasp_long*) or any of ($tagasp_classid*) or ($tagasp_short1 and $tagasp_short2 in ( filesize -100.. filesize )) or ($tagasp_short2 and ($tagasp_short1 in (0..1000) or $tagasp_short1 in ( filesize -1000.. filesize )))) and not (( any of ($perl*) or $php1 at 0 or $php2 at 0) or ((#jsp1+#jsp2+#jsp3)>0 and (#jsp4+#jsp5+#jsp6+#jsp7)>0))) and ( any of ($asp_input*) or ($asp_xml_http and any of ($asp_xml_method*)) or ( any of ($asp_form*) and any of ($asp_text*) and $asp_asp)) and ( any of ($asp_always_write*) and ( any of ($asp_write_way_one*) and any of ($asp_cr_write*)) or ( any of ($asp_streamwriter*))) and ( filesize <400 or ( filesize <6000 and 1 of ($sus*)))
}
