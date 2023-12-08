import "math"

rule WEBSHELL_ASPX_Regeorg_CSHARP
{
	meta:
		description = "Webshell regeorg aspx c# version"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		reference = "https://github.com/sensepost/reGeorg"
		hash = "c1f43b7cf46ba12cfc1357b17e4f5af408740af7ae70572c9cf988ac50260ce1"
		author = "Arnim Rupp (https://github.com/ruppde)"
		score = 75
		date = "2021/01/11"
		modified = "2023-07-05"
		hash = "479c1e1f1c263abe339de8be99806c733da4e8c1"
		hash = "38a1f1fc4e30c0b4ad6e7f0e1df5a92a7d05020b"
		hash = "e54f1a3eab740201feda235835fc0aa2e0c44ba9"
		hash = "aea0999c6e5952ec04bf9ee717469250cddf8a6f"
		os = "windows"
		filetype = "script"

	strings:
		$input_sa1 = "Request.QueryString.Get" fullword nocase wide ascii
		$input_sa2 = "Request.Headers.Get" fullword nocase wide ascii
		$sa1 = "AddressFamily.InterNetwork" fullword nocase wide ascii
		$sa2 = "Response.AddHeader" fullword nocase wide ascii
		$sa3 = "Request.InputStream.Read" nocase wide ascii
		$sa4 = "Response.BinaryWrite" nocase wide ascii
		$sa5 = "Socket" nocase wide ascii
		$georg = "Response.Write(\"Georg says, 'All seems fine'\")"
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
		filesize <300KB and (( any of ($tagasp_long*) or any of ($tagasp_classid*) or ($tagasp_short1 and $tagasp_short2 in ( filesize -100.. filesize )) or ($tagasp_short2 and ($tagasp_short1 in (0..1000) or $tagasp_short1 in ( filesize -1000.. filesize )))) and not (( any of ($perl*) or $php1 at 0 or $php2 at 0) or ((#jsp1+#jsp2+#jsp3)>0 and (#jsp4+#jsp5+#jsp6+#jsp7)>0))) and ($georg or ( all of ($sa*) and any of ($input_sa*)))
}
