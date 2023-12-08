import "pe"

rule DownExecute_A
{
	meta:
		Author = "PwC Cyber Threat Operations :: @tlansec"
		Date = "2015/04/27"
		Description = "Malware is often wrapped/protected, best to run on memory"
		Reference = "http://pwc.blogs.com/cyber_security_updates/2015/04/attacks-against-israeli-palestinian-interests.html"
		description = "Malware is often wrapped/protected, best to run on memory"
		os = "windows"
		filetype = "executable"

	strings:
		$winver1 = "win 8.1"
		$winver2 = "win Server 2012 R2"
		$winver3 = "win Srv 2012"
		$winver4 = "win srv 2008 R2"
		$winver5 = "win srv 2008"
		$winver6 = "win vsta"
		$winver7 = "win srv 2003 R2"
		$winver8 = "win hm srv"
		$winver9 = "win Strg srv 2003"
		$winver10 = "win srv 2003"
		$winver11 = "win XP prof x64 edt"
		$winver12 = "win XP"
		$winver13 = "win 2000"
		$pdb1 = "D:\\Acms\\2\\docs\\Visual Studio 2013\\Projects\\DownloadExcute\\DownloadExcute\\Release\\DownExecute.pdb"
		$pdb2 = "d:\\acms\\2\\docs\\visual studio 2013\\projects\\downloadexcute\\downloadexcute\\downexecute\\json\\rapidjson\\writer.h"
		$pdb3 = ":\\acms\\2\\docs\\visual studio 2013\\projects\\downloadexcute\\downloadexcute\\downexecute\\json\\rapidjson\\internal/stack.h"
		$pdb4 = "\\downloadexcute\\downexecute\\"
		$magic1 = "<Win Get Version Info Name Error"
		$magic2 = "P@$sw0rd$nd"
		$magic3 = "$t@k0v2rF10w"
		$magic4 = "|*|123xXx(Mutex)xXx321|*|6-21-2014-03:06PM" wide
		$str1 = "Download Excute" ascii wide fullword
		$str2 = "EncryptorFunctionPointer %d"
		$str3 = "%s\\%s.lnk"
		$str4 = "Mac:%s-Cpu:%s-HD:%s"
		$str5 = "feed back responce of host"
		$str6 = "GET Token at host"
		$str7 = "dwn md5 err"

	condition:
		all of ($winver*) or any of ($pdb*) or any of ($magic*) or 2 of ($str*)
}
