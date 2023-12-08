import "math"

rule WEBSHELL_ASP_By_String
{
	meta:
		description = "Known ASP Webshells which contain unique strings, lousy rule for low hanging fruits. Most are catched by other rules in here but maybe these catch different versions."
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		score = 75
		date = "2021-01-13"
		modified = "2023-04-05"
		hash = "f72252b13d7ded46f0a206f63a1c19a66449f216"
		hash = "bd75ac9a1d1f6bcb9a2c82b13ea28c0238360b3a7be909b2ed19d3c96e519d3d"
		hash = "56a54fe1f8023455800fd0740037d806709ffb9ece1eb9e7486ad3c3e3608d45"
		hash = "4ef5d8b51f13b36ce7047e373159d7bb42ca6c9da30fad22e083ab19364c9985"
		hash = "e90c3c270a44575c68d269b6cf78de14222f2cbc5fdfb07b9995eb567d906220"
		hash = "8a38835f179e71111663b19baade78cc3c9e1f6fcc87eb35009cbd09393cbc53"
		hash = "f2883e9461393b33feed4139c0fc10fcc72ff92924249eb7be83cb5b76f0f4ee"
		hash = "10cca59c7112dfb1c9104d352e0504f842efd4e05b228b6f34c2d4e13ffd0eb6"
		hash = "ed179e5d4d365b0332e9ffca83f66ee0afe1f1b5ac3c656ccd08179170a4d9f7"
		hash = "ce3273e98e478a7e95fccce0a3d3e8135c234a46f305867f2deacd4f0efa7338"
		hash = "65543373b8bd7656478fdf9ceeacb8490ff8976b1fefc754cd35c89940225bcf"
		hash = "de173ea8dcef777368089504a4af0804864295b75e51794038a6d70f2bcfc6f5"
		os = "windows"
		filetype = "script"

	strings:
		$asp_string1 = "tseuqer lave" wide ascii
		$asp_string2 = ":eval request(" wide ascii
		$asp_string3 = ":eval request(" wide ascii
		$asp_string4 = "SItEuRl=\"http://www.zjjv.com\"" wide ascii
		$asp_string5 = "ServerVariables(\"HTTP_HOST\"),\"gov.cn\"" wide ascii
		$asp_string6 = /e\+.-v\+.-a\+.-l/ wide ascii
		$asp_string7 = "r+x-e+x-q+x-u" wide ascii
		$asp_string8 = "add6bb58e139be10" fullword wide ascii
		$asp_string9 = "WebAdmin2Y.x.y(\"" wide ascii
		$asp_string10 = "<%if (Request.Files.Count!=0) { Request.Files[0].SaveAs(Server.MapPath(Request[" wide ascii
		$asp_string11 = "<% If Request.Files.Count <> 0 Then Request.Files(0).SaveAs(Server.MapPath(Request(" wide ascii
		$asp_string12 = "UmVxdWVzdC5JdGVtWyJ" wide ascii
		$asp_string13 = "UAdgBhAGwAKA" wide ascii
		$asp_string14 = "lAHYAYQBsACgA" wide ascii
		$asp_string15 = "ZQB2AGEAbAAoA" wide ascii
		$asp_string16 = "IAZQBxAHUAZQBzAHQAKA" wide ascii
		$asp_string17 = "yAGUAcQB1AGUAcwB0ACgA" wide ascii
		$asp_string18 = "cgBlAHEAdQBlAHMAdAAoA" wide ascii
		$asp_string19 = "\"ev\"&\"al" wide ascii
		$asp_string20 = "\"Sc\"&\"ri\"&\"p" wide ascii
		$asp_string21 = "C\"&\"ont\"&\"" wide ascii
		$asp_string22 = "\"vb\"&\"sc" wide ascii
		$asp_string23 = "\"A\"&\"do\"&\"d" wide ascii
		$asp_string24 = "St\"&\"re\"&\"am\"" wide ascii
		$asp_string25 = "*/eval(" wide ascii
		$asp_string26 = "\"e\"&\"v\"&\"a\"&\"l" nocase
		$asp_string27 = "<%eval\"\"&(\"" nocase wide ascii
		$asp_string28 = "6877656D2B736972786677752B237E232C2A" wide ascii
		$asp_string29 = "ws\"&\"cript.shell" wide ascii
		$asp_string30 = "SerVer.CreAtEoBjECT(\"ADODB.Stream\")" wide ascii
		$asp_string31 = "ASPShell - web based shell" wide ascii
		$asp_string32 = "<++ CmdAsp.asp ++>" wide ascii
		$asp_string33 = "\"scr\"&\"ipt\"" wide ascii
		$asp_string34 = "Regex regImg = new Regex(\"[a-z|A-Z]{1}:\\\\\\\\[a-z|A-Z| |0-9|\\u4e00-\\u9fa5|\\\\~|\\\\\\\\|_|{|}|\\\\.]*\");" wide ascii
		$asp_string35 = "\"she\"&\"ll." wide ascii
		$asp_string36 = "LH\"&\"TTP" wide ascii
		$asp_string37 = "<title>Web Sniffer</title>" wide ascii
		$asp_string38 = "<title>WebSniff" wide ascii
		$asp_string39 = "cript\"&\"ing" wide ascii
		$asp_string40 = "tcejbOmetsySeliF.gnitpircS" wide ascii
		$asp_string41 = "tcejbOetaerC.revreS" wide ascii
		$asp_string42 = "This file is part of A Black Path Toward The Sun (\"ABPTTS\")" wide ascii
		$asp_string43 = "if ((Request.Headers[headerNameKey] != null) && (Request.Headers[headerNameKey].Trim() == headerValueKey.Trim()))" wide ascii
		$asp_string44 = "if (request.getHeader(headerNameKey).toString().trim().equals(headerValueKey.trim()))" wide ascii
		$asp_string45 = "Response.Write(Server.HtmlEncode(ExcutemeuCmd(txtArg.Text)));" wide ascii
		$asp_string46 = "\"c\" + \"m\" + \"d\"" wide ascii
		$asp_string47 = "\".\"+\"e\"+\"x\"+\"e\"" wide ascii
		$asp_string48 = "Tas9er" fullword wide ascii
		$asp_string49 = "<%@ Page Language=\"\\u" wide ascii
		$asp_string50 = "BinaryRead(\\u" wide ascii
		$asp_string51 = "Request.\\u" wide ascii
		$asp_string52 = "System.Buffer.\\u" wide ascii
		$asp_string53 = "System.Net.\\u" wide ascii
		$asp_string54 = ".\\u0052\\u0065\\u0066\\u006c\\u0065\\u0063\\u0074\\u0069\\u006f\\u006e\"" wide ascii
		$asp_string55 = "\\u0041\\u0073\\u0073\\u0065\\u006d\\u0062\\u006c\\u0079.\\u004c\\u006f\\u0061\\u0064" wide ascii
		$asp_string56 = "\\U00000052\\U00000065\\U00000071\\U00000075\\U00000065\\U00000073\\U00000074[\"" wide ascii
		$asp_string57 = "*/\\U0000" wide ascii
		$asp_string58 = "\\U0000FFFA" wide ascii
		$asp_string59 = "\"e45e329feb5d925b\"" wide ascii
		$asp_string60 = ">POWER!shelled<" wide ascii
		$asp_string61 = "@requires xhEditor" wide ascii
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

	condition:
		filesize <200KB and (( any of ($tagasp_long*) or any of ($tagasp_classid*) or ($tagasp_short1 and $tagasp_short2 in ( filesize -100.. filesize )) or ($tagasp_short2 and ($tagasp_short1 in (0..1000) or $tagasp_short1 in ( filesize -1000.. filesize )))) and not (( any of ($perl*) or $php1 at 0 or $php2 at 0) or ((#jsp1+#jsp2+#jsp3)>0 and (#jsp4+#jsp5+#jsp6+#jsp7)>0))) and any of ($asp_string*)
}
