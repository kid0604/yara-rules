import "pe"

rule keyboy_errors
{
	meta:
		author = "Matt Brooks, @cmatthewbrooks"
		desc = "Matches the sample's shell error2 log statements"
		date = "2016-08-28"
		md5 = "495adb1b9777002ecfe22aaf52fcee93"
		description = "Matches the sample's shell error2 log statements"
		os = "windows"
		filetype = "executable"

	strings:
		$error = "Error2" ascii wide
		$s1 = "Can't find [%s]!Check the file name and try again!" ascii wide
		$s2 = "Open [%s] error! %d" ascii wide
		$s3 = "The Size of [%s] is zero!" ascii wide
		$s4 = "CreateThread DownloadFile[%s] Error!" ascii wide
		$s5 = "UploadFile [%s] Error:Connect Server Failed!" ascii wide
		$s6 = "Receive [%s] Error(Recved[%d] != Send[%d])!" ascii wide
		$s7 = "Receive [%s] ok! Use %2.2f seconds, Average speed %2.2f k/s" ascii wide
		$s8 = "CreateThread UploadFile[%s] Error!" ascii wide
		$s9 = "Ready Download [%s] ok!" ascii wide
		$s10 = "Get ControlInfo from FileClient error!" ascii wide
		$s11 = "FileClient has a error!" ascii wide
		$s12 = "VirtualAlloc SendBuff Error(%d)" ascii wide
		$s13 = "ReadFile [%s] Error(%d)..." ascii wide
		$s14 = "ReadFile [%s] Data[Readed(%d) != FileSize(%d)] Error..." ascii wide
		$s15 = "CreateThread DownloadFile[%s] Error!" ascii wide
		$s16 = "RecvData MyRecv_Info Size Error!" ascii wide
		$s17 = "RecvData MyRecv_Info Tag Error!" ascii wide
		$s18 = "SendData szControlInfo_1 Error!" ascii wide
		$s19 = "SendData szControlInfo_3 Error!" ascii wide
		$s20 = "VirtualAlloc RecvBuff Error(%d)" ascii wide
		$s21 = "RecvData Error!" ascii wide
		$s22 = "WriteFile [%s} Error(%d)..." ascii wide

	condition:
		uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550 and filesize <200KB and $error and 3 of ($s*)
}
