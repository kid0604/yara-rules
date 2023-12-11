import "pe"

rule MALWARE_Win_Chebka
{
	meta:
		author = "ditekSHen"
		description = "Detects Chebka"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "-k netsvcs" wide
		$s2 = "%ssvchost.exe -k SystemNetworkService" wide
		$s3 = "Mozilla/4.0 (compatible)" wide
		$s4 = "_kasssperskdy" wide
		$s5 = "winssyslog" wide
		$s6 = "LoaderDll%d" wide
		$s7 = "cmd.exe /c rundll32.exe shell32.dll," wide
		$s8 = /cmd.exe \/c start (chrome|msedge|firefox|iexplorer)\.exe/ wide
		$f1 = ".?AVCHVncManager@@" fullword ascii
		$f2 = ".?AVCNetstatManager@@" fullword ascii
		$f3 = ".?AVCTcpAgentListener@@" fullword ascii
		$f4 = ".?AVIUdpClientListener@@" fullword ascii
		$f5 = ".?AVCShellManager@@" fullword ascii
		$f6 = ".?AVCScreenSpy@@" fullword ascii

	condition:
		uint16(0)==0x5a4d and (5 of ($s*) or all of ($f*) or (3 of ($f*) and 3 of ($s*)) or (#s8>2 and 5 of them ))
}
