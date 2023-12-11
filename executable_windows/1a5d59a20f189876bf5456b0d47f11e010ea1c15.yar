import "pe"

rule APT_APT10_Malware_Imphash_Dec18_1
{
	meta:
		description = "Detects APT10 malware based on ImpHashes"
		author = "Florian Roth (Nextron Systems)"
		reference = "AlienVault OTX IOCs - statistical sample analysis"
		date = "2018-12-28"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and filesize <6000KB and (pe.imphash()=="0556ff5e5f8744bff47d4921494ba46d" or pe.imphash()=="cb1194123f68a68eb14552c085b620ce" or pe.imphash()=="efad9ff8c0d2a6419bf1dd970bcd806d" or pe.imphash()=="7a861cd9c495e1d950a43cb708a22985" or pe.imphash()=="a5d0545030be75a421529c2b0be6c4bd" or pe.imphash()=="94491f4a812b0297419dc888aa4fd2a5")
}
