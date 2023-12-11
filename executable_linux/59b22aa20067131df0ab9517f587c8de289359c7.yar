rule APT_MAL_WinntiLinux_Main_AzazelFork_May19
{
	meta:
		description = "Detection of Linux variant of Winnti"
		author = "Silas Cutler (havex [@] chronicle.security), Chronicle Security"
		version = "1.0"
		date = "2019-05-15"
		TLP = "White"
		sha256 = "ae9d6848f33644795a0cc3928a76ea194b99da3c10f802db22034d9f695a0c23"
		os = "linux"
		filetype = "executable"

	strings:
		$uuid_lookup = "/usr/sbin/dmidecode  | grep -i 'UUID' |cut -d' ' -f2 2>/dev/null"
		$dbg_msg = "[advNetSrv] can not create a PF_INET socket"
		$rtti_name1 = "CNetBase"
		$rtti_name2 = "CMyEngineNetEvent"
		$rtti_name3 = "CBufferCache"
		$rtti_name4 = "CSocks5Base"
		$rtti_name5 = "CDataEngine"
		$rtti_name6 = "CSocks5Mgr"
		$rtti_name7 = "CRemoteMsg"

	condition:
		uint16(0)==0x457f and (($dbg_msg and 1 of ($rtti*)) or (5 of ($rtti*)) or ($uuid_lookup and 2 of ($rtti*)))
}
