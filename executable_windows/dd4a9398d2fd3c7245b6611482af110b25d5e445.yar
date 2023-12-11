rule Malware_QA_update
{
	meta:
		description = "VT Research QA uploaded malware - file update.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "VT Research QA"
		date = "2016-08-29"
		score = 80
		hash1 = "6d805533623d7063241620eec38b7eb9b625533ccadeaf4f6c2cc6db32711541"
		hash2 = "6415b45f5bae6429dd5d92d6cae46e8a704873b7090853e68e80cd179058903e"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "UnActiveOfflineKeylogger" fullword ascii
		$x2 = "BTRESULTDownload File|Mass Download : File Downloaded , Executing new one in temp dir...|" fullword ascii
		$x3 = "ActiveOnlineKeylogger" fullword ascii
		$x4 = "C:\\Users\\DarkCoderSc\\" ascii
		$x5 = "Celesty Binder\\Stub\\STATIC\\Stub.pdb" ascii
		$x6 = "BTRESULTUpdate from URL|Update : File Downloaded , Executing new one in temp dir...|" fullword ascii
		$s1 = "MSRSAAP.EXE" fullword wide
		$s2 = "Command successfully executed!|" fullword ascii
		$s3 = "BTMemoryLoadLibary: Get DLLEntyPoint failed" fullword ascii
		$s4 = "I wasn't able to open the hosts file, maybe because UAC is enabled in remote computer!" fullword ascii
		$s5 = "\\Internet Explorer\\iexplore.exe" ascii
		$s6 = "ping 127.0.0.1 -n 4 > NUL && \"" fullword ascii
		$s7 = "BTMemoryGetProcAddress: DLL doesn't export anything" fullword ascii
		$s8 = "POST /index.php/1.0" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <3000KB and (1 of ($x*) or 3 of ($s*))) or ( all of them )
}
