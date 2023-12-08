import "pe"

rule HackTool_MSIL_SharPivot_3_alt_1
{
	meta:
		description = "This rule looks for .NET PE files that have the strings of various method names in the SharPivot code."
		md5 = "e4efa759d425e2f26fbc29943a30f5bd"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		os = "windows"
		filetype = "executable"

	strings:
		$msil = "_CorExeMain" ascii wide
		$str1 = "SharPivot" ascii wide
		$str2 = "ParseArgs" ascii wide
		$str3 = "GenRandomString" ascii wide
		$str4 = "ScheduledTaskExists" ascii wide
		$str5 = "ServiceExists" ascii wide
		$str6 = "lpPassword" ascii wide
		$str7 = "execute" ascii wide
		$str8 = "WinRM" ascii wide
		$str9 = "SchtaskMod" ascii wide
		$str10 = "PoisonHandler" ascii wide
		$str11 = "SCShell" ascii wide
		$str12 = "SchtaskMod" ascii wide
		$str13 = "ServiceHijack" ascii wide
		$str14 = "ServiceHijack" ascii wide
		$str15 = "commandArg" ascii wide
		$str16 = "payloadPath" ascii wide
		$str17 = "Schtask" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and $msil and all of ($str*)
}
