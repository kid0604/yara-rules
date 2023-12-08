rule Chafer_Mimikatz_Custom
{
	meta:
		description = "Detects Custom Mimikatz Version"
		author = "Florian Roth (Nextron Systems) / Markus Neis"
		reference = "https://nyotron.com/wp-content/uploads/2018/03/Nyotron-OilRig-Malware-Report-March-2018b.pdf"
		date = "2018-03-22"
		hash1 = "9709afeb76532566ee3029ecffc76df970a60813bcac863080cc952ad512b023"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "C:\\Users\\win7p\\Documents\\mi-back\\" ascii

	condition:
		uint16(0)==0x5a4d and filesize <3000KB and 1 of them
}
