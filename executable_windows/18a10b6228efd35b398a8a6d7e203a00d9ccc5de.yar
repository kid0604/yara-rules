rule Lazarus_tool_smbscan
{
	meta:
		description = "SMB scan tool in Lazarus"
		author = "JPCERT/CC Incident Response Group"
		hash1 = "d16163526242508d6961f061aaffe3ae5321bd64d8ceb6b2788f1570757595fc"
		hash2 = "11b29200f0696041dd607d0664f1ebf5dba2e2538666db663b3077d77f883195"
		os = "windows"
		filetype = "executable"

	strings:
		$toolstr1 = "Scan.exe StartIP EndIP ThreadCount logfilePath [Username Password Deep]" ascii
		$toolstr2 = "%s%-30s%I64d\t%04d-%02d-%02d %02d:%02d" ascii
		$toolstr3 = "%s%-30s(DIR)\t%04d-%02d-%02d %02d:%02d" ascii
		$toolstr4 = "%s U/P not Correct! - %d" ascii
		$toolstr5 = "%s %-20S%-30s%S" ascii
		$toolstr6 = "%s - %s:(Username - %s / Password - %s" ascii

	condition:
		4 of ($toolstr*)
}
