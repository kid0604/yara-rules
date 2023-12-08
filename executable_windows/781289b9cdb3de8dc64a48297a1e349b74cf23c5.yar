rule WEBSHELL_ASPX_DLL_MOVEit_Jun23_1
{
	meta:
		description = "Detects compiled ASPX web shells found being used in MOVEit Transfer exploitation"
		author = "Florian Roth"
		reference = "https://www.trustedsec.com/blog/critical-vulnerability-in-progress-moveit-transfer-technical-analysis-and-recommendations/?utm_content=251159938&utm_medium=social&utm_source=twitter&hss_channel=tw-403811306"
		date = "2023-06-01"
		score = 85
		hash1 = "6cbf38f5f27e6a3eaf32e2ac73ed02898cbb5961566bb445e3c511906e2da1fa"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "human2_aspx" ascii fullword
		$x2 = "X-siLock-Comment" wide
		$x3 = "x-siLock-Step1" wide
		$a1 = "MOVEit.DMZ.Core.Data" ascii fullword

	condition:
		uint16(0)==0x5a4d and filesize <40KB and (1 of ($x*) and $a1) or all of them
}
