import "math"

rule webshell_asp_generic
{
	meta:
		description = "Detect the risk of malicious file (aspwebsell)  Rule 37"
		os = "windows"
		filetype = "script"

	strings:
		$asp_much_sus7 = "Web Shell" nocase
		$asp_much_sus8 = "WebShell" nocase
		$asp_much_sus3 = "hidded shell"
		$asp_much_sus4 = "WScript.Shell.1" nocase
		$asp_much_sus5 = "AspExec"
		$asp_much_sus14 = "\\pcAnywhere\\" nocase
		$asp_much_sus15 = "antivirus" nocase
		$asp_much_sus16 = "McAfee" nocase
		$asp_much_sus17 = "nishang"
		$asp_much_sus18 = "\"unsafe" fullword wide ascii
		$asp_much_sus19 = "'unsafe" fullword wide ascii
		$asp_much_sus28 = "exploit" fullword wide ascii
		$asp_much_sus30 = "TVqQAAMAAA" wide ascii
		$asp_much_sus31 = "HACKED" fullword wide ascii
		$asp_much_sus32 = "hacked" fullword wide ascii
		$asp_much_sus33 = "hacker" wide ascii
		$asp_much_sus34 = "grayhat" nocase wide ascii
		$asp_much_sus35 = "Microsoft FrontPage" wide ascii
		$asp_much_sus36 = "Rootkit" wide ascii
		$asp_much_sus37 = "rootkit" wide ascii
		$asp_much_sus38 = "/*-/*-*/" wide ascii
		$asp_much_sus39 = "u\"+\"n\"+\"s" wide ascii
		$asp_much_sus40 = "\"e\"+\"v" wide ascii
		$asp_much_sus41 = "a\"+\"l\"" wide ascii
		$asp_much_sus42 = "\"+\"(\"+\"" wide ascii
		$asp_much_sus43 = "q\"+\"u\"" wide ascii
		$asp_much_sus44 = "\"u\"+\"e" wide ascii
		$asp_much_sus45 = "/*//*/" wide ascii
		$asp_much_sus46 = "(\"/*/\"" wide ascii
		$asp_much_sus47 = "eval(eval(" wide ascii
		$asp_much_sus48 = "Shell.Users" wide ascii
		$asp_much_sus49 = "PasswordType=Regular" wide ascii
		$asp_much_sus50 = "-Expire=0" wide ascii
		$asp_much_sus51 = "sh\"&\"el" wide ascii
		$asp_gen_sus1 = /:\s{0,20}eval}/ nocase wide ascii
		$asp_gen_sus2 = /\.replace\(\/\w\/g/ nocase wide ascii
		$asp_gen_sus6 = "self.delete"
		$asp_gen_sus9 = "\"cmd /c" nocase
		$asp_gen_sus10 = "\"cmd\"" nocase
		$asp_gen_sus11 = "\"cmd.exe" nocase
		$asp_gen_sus12 = "%comspec%" wide ascii
		$asp_gen_sus13 = "%COMSPEC%" wide ascii
		$asp_gen_sus18 = "Hklm.GetValueNames();" nocase
		$asp_gen_sus19 = "http://schemas.microsoft.com/exchange/" wide ascii
		$asp_gen_sus21 = "\"upload\"" wide ascii
		$asp_gen_sus22 = "\"Upload\"" wide ascii
		$asp_gen_sus25 = "shell_" wide ascii
		$asp_gen_sus29 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" fullword wide ascii
		$asp_gen_sus30 = "serv-u" wide ascii
		$asp_gen_sus31 = "Serv-u" wide ascii
		$asp_gen_sus32 = "Army" fullword wide ascii
		$asp_slightly_sus1 = "<pre>" wide ascii
		$asp_slightly_sus2 = "<PRE>" wide ascii
		$asp_gen_obf1 = "\"+\"" wide ascii
		$fp1 = "DataBinder.Eval"
		$fp2 = "B2BTools"
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
		$dex = { 64 65 ( 78 | 79 ) 0a 30 }
		$pack = { 50 41 43 4b 00 00 00 02 00 }
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
		$asp_payload0 = "eval_r" fullword nocase wide ascii
		$asp_payload1 = /\beval\s/ nocase wide ascii
		$asp_payload2 = /\beval\(/ nocase wide ascii
		$asp_payload3 = /\beval\"\"/ nocase wide ascii
		$asp_payload4 = /:\s{0,10}eval\b/ nocase wide ascii
		$asp_payload8 = /\bexecute\s?\(/ nocase wide ascii
		$asp_payload9 = /\bexecute\s[\w"]/ nocase wide ascii
		$asp_payload11 = "WSCRIPT.SHELL" fullword nocase wide ascii
		$asp_payload13 = "ExecuteGlobal" fullword nocase wide ascii
		$asp_payload14 = "ExecuteStatement" fullword nocase wide ascii
		$asp_payload15 = "ExecuteStatement" fullword nocase wide ascii
		$asp_multi_payload_one1 = "CreateObject" nocase fullword wide ascii
		$asp_multi_payload_one2 = "addcode" fullword wide ascii
		$asp_multi_payload_one3 = /\.run\b/ wide ascii
		$asp_multi_payload_two1 = "CreateInstanceFromVirtualPath" fullword wide ascii
		$asp_multi_payload_two2 = "ProcessRequest" fullword wide ascii
		$asp_multi_payload_two3 = "BuildManager" fullword wide ascii
		$asp_multi_payload_three1 = "System.Diagnostics" wide ascii
		$asp_multi_payload_three2 = "Process" fullword wide ascii
		$asp_multi_payload_three3 = ".Start" wide ascii
		$asp_multi_payload_four1 = "CreateObject" fullword nocase wide ascii
		$asp_multi_payload_four2 = "TransformNode" fullword nocase wide ascii
		$asp_multi_payload_four3 = "loadxml" fullword nocase wide ascii
		$asp_multi_payload_five1 = "ProcessStartInfo" fullword nocase wide ascii
		$asp_multi_payload_five2 = ".Start" nocase wide ascii
		$asp_multi_payload_five3 = ".Filename" nocase wide ascii
		$asp_multi_payload_five4 = ".Arguments" nocase wide ascii
		$asp_always_write1 = /\.write/ nocase wide ascii
		$asp_always_write2 = /\.swrite/ nocase wide ascii
		$asp_write_way_one2 = "SaveToFile" fullword nocase wide ascii
		$asp_write_way_one3 = "CREAtEtExtFiLE" fullword nocase wide ascii
		$asp_cr_write1 = "CreateObject(" fullword nocase wide ascii
		$asp_cr_write2 = "CreateObject (" fullword nocase wide ascii
		$asp_streamwriter1 = "streamwriter" fullword nocase wide ascii
		$asp_streamwriter2 = "filestream" fullword nocase wide ascii
		$tagasp_capa_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
		$tagasp_capa_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
		$tagasp_capa_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
		$tagasp_capa_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
		$tagasp_capa_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii

	condition:
		(( any of ($tagasp_long*) or any of ($tagasp_classid*) or ($tagasp_short1 and $tagasp_short2 in ( filesize -100.. filesize )) or ($tagasp_short2 and ($tagasp_short1 in (0..1000) or $tagasp_short1 in ( filesize -1000.. filesize )))) and not (( any of ($perl*) or $php1 at 0 or $php2 at 0) or ((#jsp1+#jsp2+#jsp3)>0 and (#jsp4+#jsp5+#jsp6+#jsp7)>0))) and not ( uint16(0)==0x5a4d or $dex at 0 or $pack at 0 or uint16(0)==0x4b50) and ( any of ($asp_input*) or ($asp_xml_http and any of ($asp_xml_method*)) or ( any of ($asp_form*) and any of ($asp_text*) and $asp_asp)) and ( any of ($asp_payload*) or all of ($asp_multi_payload_one*) or all of ($asp_multi_payload_two*) or all of ($asp_multi_payload_three*) or all of ($asp_multi_payload_four*) or all of ($asp_multi_payload_five*)) and not any of ($fp*) and (( filesize <3KB and (1 of ($asp_slightly_sus*))) or ( filesize <25KB and (1 of ($asp_much_sus*) or 1 of ($asp_gen_sus*) or (#asp_gen_obf1>2))) or ( filesize <50KB and (1 of ($asp_much_sus*) or 3 of ($asp_gen_sus*) or (#asp_gen_obf1>6))) or ( filesize <150KB and (1 of ($asp_much_sus*) or 4 of ($asp_gen_sus*) or (#asp_gen_obf1>6) or (( any of ($asp_always_write*) and ( any of ($asp_write_way_one*) and any of ($asp_cr_write*)) or ( any of ($asp_streamwriter*))) and (1 of ($asp_much_sus*) or 2 of ($asp_gen_sus*) or (#asp_gen_obf1>3))))) or ( filesize <100KB and ( any of ($tagasp_capa_classid*))))
}
