rule HKTL_EXPL_POC_NET_SharePoint_CVE_2023_29357_Sep23_1
{
	meta:
		description = "Detects a C# POC to exploit CVE-2023-29357 on Microsoft SharePoint servers"
		author = "Florian Roth"
		reference = "https://github.com/LuemmelSec/CVE-2023-29357"
		date = "2023-10-01"
		score = 80
		os = "windows"
		filetype = "script"

	strings:
		$x1 = "{f22d2de0-606b-4d16-98d5-421f3f1ba8bc}" ascii wide
		$x2 = "{F22D2DE0-606B-4D16-98D5-421F3F1BA8BC}" ascii wide
		$s1 = "Bearer"
		$s2 = "hashedprooftoken"
		$s3 = "/_api/web/"
		$s4 = "X-PROOF_TOKEN"
		$s5 = "00000003-0000-0ff1-ce00-000000000000"
		$s6 = "IsSiteAdmin"

	condition:
		uint16(0)==0x5a4d and filesize <800KB and (1 of ($x*) or all of ($s*))
}
