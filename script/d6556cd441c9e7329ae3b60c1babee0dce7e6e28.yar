import "math"

rule WEBSHELL_ASP_SQL
{
	meta:
		description = "ASP webshell giving SQL access. Might also be a dual use tool."
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		score = 75
		date = "2021/03/14"
		modified = "2023-07-05"
		hash = "216c1dd950e0718e35bc4834c5abdc2229de3612"
		hash = "ffe44e9985d381261a6e80f55770833e4b78424bn"
		hash = "3d7cd32d53abc7f39faed133e0a8f95a09932b64"
		hash = "f19cc178f1cfad8601f5eea2352cdbd2d6f94e7e"
		hash = "cafc4ede15270ab3f53f007c66e82627a39f4d0f"
		os = "windows"
		filetype = "script"

	strings:
		$sql1 = "SqlConnection" fullword wide ascii
		$sql2 = "SQLConnection" fullword wide ascii
		$sql3 = "System" fullword wide ascii
		$sql4 = "Data" fullword wide ascii
		$sql5 = "SqlClient" fullword wide ascii
		$sql6 = "SQLClient" fullword wide ascii
		$sql7 = "Open" fullword wide ascii
		$sql8 = "SqlCommand" fullword wide ascii
		$sql9 = "SQLCommand" fullword wide ascii
		$o_sql1 = "SQLOLEDB" fullword wide ascii
		$o_sql2 = "CreateObject" fullword wide ascii
		$o_sql3 = "open" fullword wide ascii
		$a_sql1 = "ADODB.Connection" fullword wide ascii
		$a_sql2 = "adodb.connection" fullword wide ascii
		$a_sql3 = "CreateObject" fullword wide ascii
		$a_sql4 = "createobject" fullword wide ascii
		$a_sql5 = "open" fullword wide ascii
		$c_sql1 = "System.Data.SqlClient" fullword wide ascii
		$c_sql2 = "sqlConnection" fullword wide ascii
		$c_sql3 = "open" fullword wide ascii
		$sus1 = "shell" fullword nocase wide ascii
		$sus2 = "xp_cmdshell" fullword nocase wide ascii
		$sus3 = "aspxspy" fullword nocase wide ascii
		$sus4 = "_KillMe" wide ascii
		$sus5 = "cmd.exe" fullword wide ascii
		$sus6 = "cmd /c" fullword wide ascii
		$sus7 = "net user" fullword wide ascii
		$sus8 = "\\x2D\\x3E\\x7C" wide ascii
		$sus9 = "Hacker" fullword wide ascii
		$sus10 = "hacker" fullword wide ascii
		$sus11 = "HACKER" fullword wide ascii
		$sus12 = "webshell" wide ascii
		$sus13 = "equest[\"sql\"]" wide ascii
		$sus14 = "equest(\"sql\")" wide ascii
		$sus15 = { e5 bc 80 e5 a7 8b e5 af bc e5 }
		$sus16 = "\"sqlCommand\"" wide ascii
		$sus17 = "\"sqlcommand\"" wide ascii
		$slightly_sus3 = "SHOW COLUMNS FROM " wide ascii
		$slightly_sus4 = "show columns from " wide ascii
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

	condition:
		(( any of ($tagasp_long*) or any of ($tagasp_classid*) or ($tagasp_short1 and $tagasp_short2 in ( filesize -100.. filesize )) or ($tagasp_short2 and ($tagasp_short1 in (0..1000) or $tagasp_short1 in ( filesize -1000.. filesize )))) and not (( any of ($perl*) or $php1 at 0 or $php2 at 0) or ((#jsp1+#jsp2+#jsp3)>0 and (#jsp4+#jsp5+#jsp6+#jsp7)>0))) and ( any of ($asp_input*) or ($asp_xml_http and any of ($asp_xml_method*)) or ( any of ($asp_form*) and any of ($asp_text*) and $asp_asp)) and (6 of ($sql*) or all of ($o_sql*) or 3 of ($a_sql*) or all of ($c_sql*)) and (( filesize <150KB and any of ($sus*)) or ( filesize <5KB and any of ($slightly_sus*)))
}
