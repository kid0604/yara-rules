import "math"

rule WEBSHELL_ASP_Nano
{
	meta:
		description = "Generic ASP webshell which uses any eval/exec function"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		score = 75
		date = "2021/01/13"
		modified = "2023-04-05"
		hash = "3b7910a499c603715b083ddb6f881c1a0a3a924d"
		hash = "990e3f129b8ba409a819705276f8fa845b95dad0"
		hash = "22345e956bce23304f5e8e356c423cee60b0912c"
		hash = "c84a6098fbd89bd085526b220d0a3f9ab505bcba"
		hash = "b977c0ad20dc738b5dacda51ec8da718301a75d7"
		hash = "c69df00b57fd127c7d4e0e2a40d2f6c3056e0af8bfb1925938060b7e0d8c630f"
		hash = "f3b39a5da1cdde9acde077208e8e5b27feb973514dab7f262c7c6b2f8f11eaa7"
		hash = "0e9d92807d990144c637d8b081a6a90a74f15c7337522874cf6317092ea2d7c1"
		hash = "ebbc485e778f8e559ef9c66f55bb01dc4f5dcce9c31ccdd150e2c702c4b5d9e1"
		hash = "44b4068bfbbb8961e16bae238ad23d181ac9c8e4fcb4b09a66bbcd934d2d39ee"
		hash = "c5a4e188780b5513f34824904d56bf6e364979af6782417ccc5e5a8a70b4a95a"
		hash = "41a3cc668517ec207c990078bccfc877e239b12a7ff2abe55ff68352f76e819c"
		hash = "2faad5944142395794e5e6b90a34a6204412161f45e130aeb9c00eff764f65fc"
		hash = "d0c5e641120b8ea70a363529843d9f393074c54af87913b3ab635189fb0c84cb"
		hash = "28cfcfe28419a399c606bf96505bc68d6fe05624dba18306993f9fe0d398fbe1"
		os = "windows"
		filetype = "script"

	strings:
		$susasp1 = "/*-/*-*/"
		$susasp2 = "(\"%1"
		$susasp3 = /[Cc]hr\([Ss]tr\(/
		$susasp4 = "cmd.exe"
		$susasp5 = "cmd /c"
		$susasp7 = "FromBase64String"
		$susasp8 = "UmVxdWVzdC"
		$susasp9 = "cmVxdWVzdA"
		$susasp10 = "/*//*/"
		$susasp11 = "(\"/*/\""
		$susasp12 = "eval(eval("
		$fp1 = "eval a"
		$fp2 = "'Eval'"
		$fp3 = "Eval(\""
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
		$asp_cr_write1 = "CreateObject(" nocase wide ascii
		$asp_cr_write2 = "CreateObject (" nocase wide ascii
		$asp_streamwriter1 = "streamwriter" fullword nocase wide ascii
		$asp_streamwriter2 = "filestream" fullword nocase wide ascii

	condition:
		(( any of ($tagasp_long*) or any of ($tagasp_classid*) or ($tagasp_short1 and $tagasp_short2 in ( filesize -100.. filesize )) or ($tagasp_short2 and ($tagasp_short1 in (0..1000) or $tagasp_short1 in ( filesize -1000.. filesize )))) and not (( any of ($perl*) or $php1 at 0 or $php2 at 0) or ((#jsp1+#jsp2+#jsp3)>0 and (#jsp4+#jsp5+#jsp6+#jsp7)>0))) and (( any of ($asp_payload*) or all of ($asp_multi_payload_one*) or all of ($asp_multi_payload_two*) or all of ($asp_multi_payload_three*) or all of ($asp_multi_payload_four*) or all of ($asp_multi_payload_five*)) or ( any of ($asp_always_write*) and ( any of ($asp_write_way_one*) and any of ($asp_cr_write*)) or ( any of ($asp_streamwriter*)))) and not any of ($fp*) and ( filesize <200 or ( filesize <1000 and any of ($susasp*)))
}
