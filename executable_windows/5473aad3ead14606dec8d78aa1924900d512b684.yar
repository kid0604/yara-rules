import "pe"

rule APT_Backdoor_Win_GoRat_Memory_alt_1
{
	meta:
		description = "Identifies GoRat malware in memory based on strings."
		md5 = "3b926b5762e13ceec7ac3a61e85c93bb"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		os = "windows"
		filetype = "executable"

	strings:
		$rat1 = "rat/modules/socks.(*HTTPProxyClient).beacon" fullword
		$rat2 = "rat.(*Core).generateBeacon" fullword
		$rat3 = "rat.gJitter" fullword
		$rat4 = "rat/comms.(*protectedChannel).SendCmdResponse" fullword
		$rat5 = "rat/modules/filemgmt.(*acquire).NewCommandExecution" fullword
		$rat6 = "rat/modules/latlisten.(*latlistensrv).handleCmd" fullword
		$rat7 = "rat/modules/netsweeper.(*netsweeperRunner).runSweep" fullword
		$rat8 = "rat/modules/netsweeper.(*Pinger).listen" fullword
		$rat9 = "rat/modules/socks.(*HTTPProxyClient).beacon" fullword
		$rat10 = "rat/platforms/win/dyloader.(*memoryLoader).ExecutePluginFunction" fullword
		$rat11 = "rat/platforms/win/modules/namedpipe.(*dummy).Open" fullword
		$winblows = "rat/platforms/win.(*winblows).GetStage" fullword

	condition:
		$winblows or 3 of ($rat*)
}
