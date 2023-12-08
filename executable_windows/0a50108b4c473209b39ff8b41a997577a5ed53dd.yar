rule Rootkit_FiveSys
{
	meta:
		description = "Detect the risk of Malware FiveSys Rule 1"
		hash1 = "cce24ebdd344c8184dbaa0a0c4a65c7d952a11f6608fe23d562a4d1178915eac"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 %s " fullword ascii
		$s2 = "GET %s%s HTTP/1.1" fullword ascii
		$s3 = "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 sysWeb/1.0.1 " fullword ascii
		$s4 = "D:\\record.txt" fullword ascii
		$s5 = "number=%s;name=%s;switch=%s;server=%s;tag=%s;altitude=%s;serverDownloadFileName=%s;serverDownloadFileMd5=%s;" fullword ascii
		$s6 = "%d - fileName=%s result=%s DownFile=%s" fullword ascii
		$s7 = "/driverfile/Jck.txt" fullword ascii
		$s8 = "/driverfile/shuiliasafao.txt" fullword ascii
		$s9 = "\\FiveSys_1\\x64\\Debug\\FiveSys.pdb" fullword ascii
		$s10 = "/api/drive_config/driveDownloadFileList" fullword ascii
		$s11 = "[%s] CreateMiniKey failed!Error code:%x" fullword ascii
		$s12 = "Host: %d.%d.%d.%d" fullword ascii
		$s13 = "serverDownloadFileMd5" fullword ascii
		$s14 = "/api/safe/checkver?name=FiveSys_1.sys&ver=" fullword ascii
		$s15 = "Haining shengdun Network Information Technology Co., Ltd" fullword ascii
		$s16 = "\\cdriversock.cpp" fullword ascii
		$s17 = "FiveSys_1.sys\",\"md5\":\"" fullword ascii
		$s18 = "/api/popup/fiveDriveCheckdownloadfile?filelist=[{\"name\":\"" fullword ascii
		$s19 = "[%s] StartMinifilter failed!Error code:%x" fullword ascii
		$s20 = "[%s] CreateMiniKey success!" fullword ascii

	condition:
		uint16(0)==0x5a4d and 8 of them
}
