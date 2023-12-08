import "pe"

rule GoldDragon_malware_Feb18_1
{
	meta:
		description = "Detects malware from Gold Dragon report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securingtomorrow.mcafee.com/mcafee-labs/gold-dragon-widens-olympics-malware-attacks-gains-permanent-presence-on-victims-systems/"
		date = "2018-02-03"
		score = 90
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and filesize <300KB and (pe.imphash()=="168c2f7752511dfd263a83d5d08a90db" or pe.imphash()=="0606858bdeb129de33a2b095d7806e74" or pe.imphash()=="51d992f5b9e01533eb1356323ed1cb0f" or pe.imphash()=="bb801224abd8562f9ee8fb261b75e32a")
}
